#![feature(int_roundings)]

mod structs;
use crate::structs::{BlockGroupDescriptor, DirectoryEntry, Inode, Superblock, TypePerm, TypeIndicator};
use std::mem;
use null_terminated::NulStr;
use uuid::Uuid;
use zerocopy::{ByteSliceMut, AsBytes};
use std::fmt;
use rustyline::{DefaultEditor, Result};
use std::fs::File;//could try to read in fs with this
use std::io::{Read, Write};

#[repr(C)]
#[derive(Debug)]
pub struct Ext2 {
    pub superblock: &'static mut Superblock,
    pub block_groups: &'static mut [BlockGroupDescriptor],
    pub blocks: Vec<&'static mut [u8]>,
    pub block_size: usize,
    pub uuid: Uuid,
    pub block_offset: usize, // <- our "device data" actually starts at this index'th block of the device
                             // so we have to subtract this number before indexing blocks[]
}

const EXT2_MAGIC: u16 = 0xef53;
const EXT2_START_OF_SUPERBLOCK: usize = 1024;
const EXT2_END_OF_SUPERBLOCK: usize = 2048;

impl Ext2 {
    pub fn new<B: ByteSliceMut + std::fmt::Debug>(device_bytes: B, start_addr: usize) -> Ext2 {
        // https://wiki.osdev.org/Ext2#Superblock
        // parse into Ext2 struct - without copying

        // the superblock goes from bytes 1024 -> 2047
        let header_body_bytes = device_bytes.split_at(EXT2_END_OF_SUPERBLOCK);

        let superblock = unsafe {
            &mut *(header_body_bytes
                .0
                .split_at(EXT2_START_OF_SUPERBLOCK)
                .1
                .as_mut_ptr() as *mut Superblock)
        };
        assert_eq!(superblock.magic, EXT2_MAGIC);
        // at this point, we strongly suspect these bytes are indeed an ext2 filesystem

        println!("superblock:\n{:?}", superblock);
        println!("size of Inode struct: {}", mem::size_of::<Inode>());

        let block_group_count = superblock
            .blocks_count
            .div_ceil(superblock.blocks_per_group) as usize;

        let block_size: usize = 1024 << superblock.log_block_size;
        println!(
            "there are {} block groups and block_size = {}",
            block_group_count, block_size
        );
        let block_groups_rest_bytes = header_body_bytes.1.split_at(block_size);

        let block_groups = unsafe {
            std::slice::from_raw_parts_mut(
                block_groups_rest_bytes.0.as_ptr() as *mut BlockGroupDescriptor,
                block_group_count,
            )
        };

        println!("block group 0: {:?}", block_groups[0]);

        let mut blocks  = unsafe {
            std::slice::from_raw_parts_mut(
                block_groups_rest_bytes.1.as_ptr() as *mut u8,
                // would rather use: device_bytes.as_ptr(),
                superblock.blocks_count as usize * block_size,
            )
        }
        .chunks_mut(block_size)
        .collect::<Vec<&'static mut [u8]>>();

        let offset_bytes = (blocks[0].as_ptr() as usize) - start_addr;
        let block_offset = offset_bytes / block_size;
        blocks.truncate(blocks.len() - block_offset);
        let uuid = Uuid::from_bytes(superblock.fs_id);
        Ext2 {
            superblock,
            block_groups,
            blocks,
            block_size,
            uuid,
            block_offset,
        }
    }

    // given a (1-indexed) inode number, return that #'s inode structure
    pub fn get_inode(&self, inode: usize) -> &Inode {
        let group: usize = (inode - 1) / self.superblock.inodes_per_group as usize;
        let index: usize = (inode - 1) % self.superblock.inodes_per_group as usize;

        // println!("in get_inode, inode num = {}, index = {}, group = {}", inode, index, group);
        let inode_table_block = (self.block_groups[group].inode_table_block) as usize - self.block_offset;
        // println!("in get_inode, block number of inode table {}", inode_table_block);
        let inode_table = unsafe {
            std::slice::from_raw_parts(
                self.blocks[inode_table_block].as_ptr()
                    as *const Inode,
                self.superblock.inodes_per_group as usize,
            )
        };
        // probably want a Vec of BlockGroups in our Ext structure so we don't have to slice each time,
        // but this works for now.
        // println!("{:?}", inode_table);
        &inode_table[index]
    }
    
    pub fn get_mut_inode(&self, inode: usize) -> &mut Inode {
        let group: usize = (inode - 1) / self.superblock.inodes_per_group as usize;
        let index: usize = (inode - 1) % self.superblock.inodes_per_group as usize;

        // println!("in get_inode, inode num = {}, index = {}, group = {}", inode, index, group);
        let inode_table_block = (self.block_groups[group].inode_table_block) as usize - self.block_offset;
        // println!("in get_inode, block number of inode table {}", inode_table_block);
        let inode_table = unsafe {
            std::slice::from_raw_parts_mut(
                self.blocks[inode_table_block].as_ptr()
                    as *mut Inode,
                self.superblock.inodes_per_group as usize,
            )
        };
        // probably want a Vec of BlockGroups in our Ext structure so we don't have to slice each time,
        // but this works for now.
        // println!("{:?}", inode_table);
        &mut inode_table[index]
    }
    
    //after calling this, need to add links to prevent fragmentation
    fn alloc_inode(&mut self) -> std::io::Result<usize> {
		let mut group_num = 0;
		for block_group in self.block_groups.iter_mut(){
			if block_group.free_inodes_count > 0{
				let bitmap_ptr = self.blocks[block_group.inode_usage_addr as usize - self.block_offset].as_ptr();
				let bitmap = unsafe {
					std::slice::from_raw_parts_mut(
		                bitmap_ptr as *mut u8,
		                (self.superblock.inodes_per_group/8) as usize,
		            )
				};
				
				let byte_index = bitmap.iter().enumerate().find(|(_,&x)|x != 0xFFu8).unwrap().0;
				let new_inode_pos = bitmap[byte_index].leading_ones() as usize;
				let new_inode_index = byte_index*8 + new_inode_pos;
				let new_inode_num = new_inode_index + group_num*self.superblock.inodes_per_group as usize + 1;
				//println!("added inode {}", new_inode_num);
				
				//upkeep - inode, superblock, block group
				bitmap[byte_index] = bitmap[byte_index]^(0x80u8>>new_inode_pos);
				block_group.free_inodes_count -= 1;
				self.superblock.free_inodes_count -= 1;
				let inode = self.get_mut_inode(new_inode_num);
				inode.gid = group_num.try_into().unwrap();
				inode.size_low = 0;
				//size high must be modified by caller, in case its a directory
				//println!("allocated new inode with index {}",new_inode_num);
				return Ok(new_inode_num);
			}
			group_num += 1;
		}
		Err(std::io::Error::new(std::io::ErrorKind::Other,"no free inodes"))
	}
	
	 fn alloc_block(&mut self) -> std::io::Result<u32> {
		let mut group_num = 0;
		for block_group in self.block_groups.iter_mut(){
			if block_group.free_blocks_count > 0{
				let bitmap_ptr = self.blocks[block_group.block_usage_addr as usize - self.block_offset].as_ptr();
				let bitmap = unsafe {
					std::slice::from_raw_parts_mut(
		                bitmap_ptr as *mut u8,
		                (self.superblock.blocks_per_group/8) as usize,
		            )
				};
				
				let byte_index = bitmap.iter().enumerate().find(|(_,&x)|x != 0xFFu8).unwrap().0;
				let new_block_pos = bitmap[byte_index].leading_ones() as usize;
				let new_block_index = byte_index*8 + new_block_pos;
				let new_block_num = new_block_index + group_num*self.superblock.blocks_per_group as usize;
				//println!("added inode {}", new_inode_num);
				
				//upkeep - inode, superblock, block group
				bitmap[byte_index] = bitmap[byte_index]^(0x80u8>>new_block_pos);
				block_group.free_blocks_count -= 1;
				self.superblock.free_blocks_count -= 1;
				//println!("allocated new block at address {}",new_block_num);
				return Ok(new_block_num.try_into().unwrap());
			}
			group_num += 1;
		}
		Err(std::io::Error::new(std::io::ErrorKind::Other,"no free blocks"))
	}
	
	fn dealloc_inode(&mut self, inode_num: usize) -> std::io::Result<()> {
		let is_dir = self.get_inode(inode_num).type_perm & TypePerm::DIRECTORY == TypePerm::DIRECTORY;
//		if is_dir {
//			//decrement hard link counter for each child (should just be . and ..)
//			let children = self.read_dir_inode(inode_num)?;
//			for (child,_) in children {
//				let mut child_inode = self.get_mut_inode(child);
//				child_inode.hard_links -= 1;
//			}
//		}
		let inode = self.get_mut_inode(inode_num);
		//dealloc data blocks
		for block in inode.get_all_blocks(self) {
			self.dealloc_block(block as usize)?;
		}
		//update block group and superblock
		let group_num: usize = (inode_num - 1) / self.superblock.inodes_per_group as usize;
        let index: usize = (inode_num - 1) % self.superblock.inodes_per_group as usize;
        let group = &mut self.block_groups[group_num];
        
        let bitmap_ptr = self.blocks[group.inode_usage_addr as usize - self.block_offset].as_ptr();
		let bitmap = unsafe {
			std::slice::from_raw_parts_mut(
					bitmap_ptr as *mut u8,
					(self.superblock.inodes_per_group/8) as usize,
				)
			};
			
		bitmap[index/8] = bitmap[index/8]^(0x80u8>>(index%8));
		group.free_inodes_count += 1;
		//println!("freed inode {}", inode_num);
		if is_dir {
			group.dirs_count -=1;
		}
		self.superblock.free_inodes_count += 1;
		return Ok(());
	}
	
	fn dealloc_block(&mut self, block: usize) -> std::io::Result<()> {
		//update block group and superblock
		let group_num: usize = block / self.superblock.blocks_per_group as usize;
        let index: usize = block % self.superblock.blocks_per_group as usize;
        let group = &mut self.block_groups[group_num];
        
        let bitmap_ptr = self.blocks[group.block_usage_addr as usize - self.block_offset].as_ptr();
		let bitmap = unsafe {
			std::slice::from_raw_parts_mut(
					bitmap_ptr as *mut u8,
					(self.superblock.blocks_per_group/8) as usize,
				)
			};
			
		bitmap[index/8] = bitmap[index/8]^(0x80u8>>(index%8));
		group.free_blocks_count += 1;
		self.superblock.free_blocks_count += 1;
		return Ok(());
	}
	
	pub fn link(&mut self, link_target: usize, link_dir: usize, link_name: &str) -> std::io::Result<()> {
		//println!("calling link from source {} to target dir {} with name {}", link_target, link_dir, link_name);
		//need to get inodes here, as they may be in the same bock group and want to mutate self.blocks later
		let target_group: usize = (link_target - 1) / self.superblock.inodes_per_group as usize;
        let target_index: usize = (link_target - 1) % self.superblock.inodes_per_group as usize;

        // println!("in get_inode, inode num = {}, index = {}, group = {}", inode, index, group);
        let target_inode_table_block = (self.block_groups[target_group].inode_table_block) as usize - self.block_offset;
        let target_offset: isize = (target_index*std::mem::size_of::<Inode>()).try_into().unwrap();
        let target_inode_location = self.blocks[target_inode_table_block].as_ptr();
        // println!("in get_inode, block number of inode table {}", inode_table_block);
        let mut target = unsafe {
            &mut *(target_inode_location.offset(target_offset) as *mut Inode)
        };
        
        let dest_group: usize = (link_dir - 1) / self.superblock.inodes_per_group as usize;
        let dest_index: usize = (link_dir - 1) % self.superblock.inodes_per_group as usize;
        
        let dest_inode_table_block = (self.block_groups[dest_group].inode_table_block) as usize - self.block_offset;
        let dest_offset: isize = (dest_index*std::mem::size_of::<Inode>()).try_into().unwrap();
        let dest_inode_location = self.blocks[dest_inode_table_block].as_ptr();
        // println!("in get_inode, block number of inode table {}", inode_table_block);
        let dest = unsafe {
            &mut *(dest_inode_location.offset(dest_offset) as *mut Inode)
        };
        
        
		//make a directory entry
		let target_type = if target.type_perm & TypePerm::DIRECTORY == TypePerm::DIRECTORY {
			TypeIndicator::Directory
		} else {
			TypeIndicator::Regular
		};
		let new_entry = Self::dir_entry_as_bytes(link_target as u32, target_type, link_name);
		//println!("just made a directory entry for {}, it's under inode {} and points to inode {}", link_name, link_dir, link_target);
		//then add it to the inode contents
		let dir_entry_size = (((new_entry[5] as u16) << 8) | new_entry[4] as u16) as usize;
		
		//check if we should move to a new block
		if dest.block_space_left(&self) > 0 && dest.block_space_left(&self) < dir_entry_size  {
			//println!("moving to new block for this link");
			let last_block = dest.get_last_block(&self).unwrap();
			//edit last directory entry first to align to block
			let dir_size_left = dest.size_low as usize % self.block_size;
			let entry_ptr = self.blocks[last_block as usize - self.block_offset].as_ptr();
		    let mut byte_offset: isize = 0;
	        while byte_offset < dir_size_left as isize {
	            let mut directory = unsafe { 
		        	&mut *(entry_ptr.offset(byte_offset) as *mut DirectoryEntry) 
		    	};
		        // println!("{:?}", directory);
		        byte_offset += directory.entry_size as isize;
		        if byte_offset >= dir_size_left as isize {
					directory.entry_size += (self.block_size-dir_size_left) as u16;
				}
		    }
			
		    //now get a new block
		    //all of these call get_mut_inode again because root these are mutable references to self being passed
		    //println!("not enough space in last block of dest");
			dest.to_new_block(self)?;
		}
		//write the directory entry to the file
		//println!("appending {} bytes to dest", new_entry.len());
		dest.append_to_file(&new_entry, self)?;
		
		//then increment links counter
		target.hard_links += 1;
		Ok(())
	}
    
    pub fn add_dir(&mut self, root_inode: usize, name: &str) -> std::io::Result<usize>{
		let new_inode = self.alloc_inode()?;
		//not using link because I'm lazy and it's technically more work having to retrieve the inodes each of the three times
		//need to get inodes here, as they may be in the same bock group and want to mutate self.blocks later
		let root_group: usize = (root_inode - 1) / self.superblock.inodes_per_group as usize;
        let root_index: usize = (root_inode - 1) % self.superblock.inodes_per_group as usize;

        // println!("in get_inode, inode num = {}, index = {}, group = {}", inode, index, group);
        let root_inode_table_block = (self.block_groups[root_group].inode_table_block) as usize - self.block_offset;
        let root_offset: isize = (root_index*std::mem::size_of::<Inode>()).try_into().unwrap();
        let root_inode_location = self.blocks[root_inode_table_block].as_ptr();
        // println!("in get_inode, block number of inode table {}", inode_table_block);
        let mut root = unsafe {
            &mut *(root_inode_location.offset(root_offset) as *mut Inode)
        };
        
        let new_group: usize = (new_inode - 1) / self.superblock.inodes_per_group as usize;
        let new_index: usize = (new_inode - 1) % self.superblock.inodes_per_group as usize;
        
        let new_inode_table_block = (self.block_groups[new_group].inode_table_block) as usize - self.block_offset;
        let new_offset: isize = (new_index*std::mem::size_of::<Inode>()).try_into().unwrap();
        let new_inode_location = self.blocks[new_inode_table_block].as_ptr();
        // println!("in get_inode, block number of inode table {}", inode_table_block);
        let mut new = unsafe {
            &mut *(new_inode_location.offset(new_offset) as *mut Inode)
        };
		
		//make this add an inode, then add a directory entry to this root,
		//then add . and ..  pointing to the appropriate inodes (and update inode struct appropriately)
		let bytes_to_write = Self::dir_entry_as_bytes(new_inode as u32,TypeIndicator::Directory, name);
		let dir_entry_size = (((bytes_to_write[5] as u16) << 8) | bytes_to_write[4] as u16) as usize;
		//println!("bytes of the size are 4: {}, 5: {}",bytes_to_write[4],bytes_to_write[5]);
		
		//check if we should move to a new block
		if root.block_space_left(&self) > 0 && root.block_space_left(&self) < dir_entry_size  {
			//println!("moving to new block for this dir");
			//println!("block space left: {}, dir_entry_size: {}",root.block_space_left(&self),dir_entry_size);
			let last_block = root.get_last_block(&self).unwrap();
			//edit last directory entry first to align to block
			let dir_size_left = root.size_low as usize % self.block_size;
			let entry_ptr = self.blocks[last_block as usize - self.block_offset].as_ptr();
		    let mut byte_offset: isize = 0;
	        while byte_offset < dir_size_left as isize {
	            let mut directory = unsafe { 
		        	&mut *(entry_ptr.offset(byte_offset) as *mut DirectoryEntry) 
		    	};
		        // println!("{:?}", directory);
		        byte_offset += directory.entry_size as isize;
		        if byte_offset >= dir_size_left as isize {
					directory.entry_size += (self.block_size-dir_size_left) as u16;
				}
		    }
			
		    //now get a new block
		    //all of these call get_mut_inode again because root these are mutable references to self being passed
		    //println!("not enough space in last block of root");
			root.to_new_block(self)?;
		}
		
		//write the directory entry to the file
		//println!("appending {} bytes to root", bytes_to_write.len());
		//println!("fields of new directory entry: inode: {}, entry_size: {}, name_len: {}, type_indicator: {}, str name: {}", new_inode, dir_entry_size, name_len, 0x00u8, name);
		root.append_to_file(&bytes_to_write, self)?;
		
		
		//upkeep - inode, superblock, block group, directory entries
		// . and .. directories
		let mut tree_links = Self::dir_entry_as_bytes(new_inode as u32,TypeIndicator::Directory, ".");
		tree_links.append(&mut Self::dir_entry_as_bytes(root_inode as u32,TypeIndicator::Directory, ".."));
		
		//println!("appending {} bytes to new dir", tree_links.len());
		//println!("important fields of . directory entry: inode: {}", new_inode);
		//println!("important fields of .. directory entry: inode: {}", root_inode);
		new.append_to_file(&tree_links, self)?;
		
		//set new inode and block group values
		//update new inode
		new.hard_links += 2;
		
		//update old inode
		root.hard_links += 1;
		
		//update block group
		self.block_groups[new.gid as usize].dirs_count += 1;
		
		//set type & perms
		new.type_perm = TypePerm::DIRECTORY;
		
		//println!("performed upkeep");
		Ok(new_inode)
	}
	
	//removes target file or directory
	//assumed to be recursive, so check for contents elsewhere
	pub fn remove(&mut self, root_inode: usize, target_inode: usize, target_name: &str) -> std::io::Result<()>{
		//println!("removing {} at inode {} from dir {}",target_name,target_inode,root_inode);
		//TODO fix endless loop? (try rm lost+found)
		//this code just grabs the inode from self, as a mutable reference, without needing to keep
		//around an extra mutable reference to self
		let root_group: usize = (root_inode - 1) / self.superblock.inodes_per_group as usize;
        let root_index: usize = (root_inode - 1) % self.superblock.inodes_per_group as usize;

        // println!("in get_inode, inode num = {}, index = {}, group = {}", inode, index, group);
        let root_inode_table_block = (self.block_groups[root_group].inode_table_block) as usize - self.block_offset;
        let root_offset: isize = (root_index*std::mem::size_of::<Inode>()).try_into().unwrap();
        let root_inode_location = self.blocks[root_inode_table_block].as_ptr();
        // println!("in get_inode, block number of inode table {}", inode_table_block);
        let root = unsafe {
            &mut *(root_inode_location.offset(root_offset) as *mut Inode)
        };
        
        let target_group: usize = (target_inode - 1) / self.superblock.inodes_per_group as usize;
        let target_index: usize = (target_inode - 1) % self.superblock.inodes_per_group as usize;
        
        let target_inode_table_block = (self.block_groups[target_group].inode_table_block) as usize - self.block_offset;
        let target_inode_offset: isize = (target_index*std::mem::size_of::<Inode>()).try_into().unwrap();
        let target_inode_location = self.blocks[target_inode_table_block].as_ptr();
        // println!("in get_inode, block number of inode table {}", inode_table_block);
        let mut target = unsafe {
            &mut *(target_inode_location.offset(target_inode_offset) as *mut Inode)
        };
		
		//remove the directory entry in root
        let dir_size = root.size_low;
		let dir_blocks = root.get_all_blocks(&self);
        let mut target_block = (0,0); //(block,index in inode)
        let mut target_offset = 0;
        let mut remaining_dirs = Vec::new();
        let mut last_entry_size = 0;
        //find the target block
        for i in 0..dir_blocks.len() {
			let entry_ptr = self.blocks[dir_blocks[i] as usize - self.block_offset].as_ptr();
		    let mut byte_offset: isize = 0;
	        while byte_offset < self.block_size.try_into().unwrap() && (i*self.block_size) as isize + byte_offset < dir_size as isize { 
	            let directory = unsafe { 
		        	&*(entry_ptr.offset(byte_offset) as *const DirectoryEntry) 
		    	};
		    	//println!("processing {}", directory.name.to_string());
		    	//if we're past our target, add to the list of dirs
		        if target_block.0 != 0 {
					//println!("adding {} to the list of directories", directory.name.to_string());
					remaining_dirs.push(directory);
				}
				if directory.inode == target_inode as u32 && directory.name.to_string().eq(target_name) {
					target_block = (dir_blocks[i],i);
					target_offset = byte_offset;
					//println!("found {}!", directory.name.to_string());
				} else {
					last_entry_size = directory.entry_size;
					//println!("setting last entry size to {}", last_entry_size);
				}
				//assume that the directory size was aligned properly to the block
		        byte_offset += directory.entry_size as isize;
		    }
		    if target_block.0 != 0 {break;}
		}
		if target_block.0 == 0 {return Err(std::io::Error::new(std::io::ErrorKind::Other,"target does not exist"));}
		
		//rearrange directory entries to prevent fragmentation, but use minimal movement
		//pack the target block
		let old_data = &self.blocks[target_block.0 as usize - self.block_offset];
		let mut target_data: Vec<u8> = Vec::new();
		target_data.extend_from_slice(&old_data[..target_offset as usize]);
		//println!("target_data goes up to {}", target_data.len());
		for dir in remaining_dirs {
			//println!("adding {} back to the block", dir.name.to_string());
			let mut entry = Self::dir_entry_as_bytes(dir.inode,dir.type_indicator,&dir.name.to_string());
			target_data.append(&mut entry);
			//println!("target_data now goes up to {}", target_data.len());
		}
		let mut extra_space = self.block_size - target_data.len();
		
		
		//get the entries from the last block and move to target block, unless target is last block
		if target_block.1 != dir_blocks.len()-1 {
			//println!("doing stuff to the last block, aka index {}",dir_blocks.len()-1);
			let mut last_entries = Vec::new();
			let entry_ptr = self.blocks[dir_blocks[dir_blocks.len()-1] as usize - self.block_offset].as_ptr();
		    let mut byte_offset: isize = 0;
	        while byte_offset < self.block_size.try_into().unwrap() && ((dir_blocks.len()-1)*self.block_size) as isize + byte_offset < dir_size as isize { 
	            let directory = unsafe { 
		        	&*(entry_ptr.offset(byte_offset) as *const DirectoryEntry) 
		    	};
		    	//assemble list of dirs
				last_entries.push(directory);
				//println!("found {} in the last block", directory.name.to_string());
				//assume that the directory size was aligned properly to the block
		        byte_offset += directory.entry_size as isize;
		    }
		    //now pull from here to fill in the remaining block size, then reconstruct last block
		    //okay this for loop could definitely just go in the while loop above, but this might be nicer organizationally?
			let mut new_last_data: Vec<u8> = Vec::new();
			for dir in last_entries {
				let mut entry = Self::dir_entry_as_bytes(dir.inode,dir.type_indicator,&dir.name.to_string());
				if ((entry[5] as usize) << 8) | entry[4] as usize <= extra_space {
					last_entry_size = ((entry[5] as u16) << 8) | entry[4] as u16;
					extra_space -= last_entry_size as usize;
					target_data.append(&mut entry);
					//println!("moved {} to earlier block", dir.name.to_string());
				} else {
					new_last_data.append(&mut entry);
					//println!("kept {} in last block", dir.name.to_string());
				}
			}
			//size the last entry appropriately, if this isn't the last block
			if new_last_data.len() > 0 {
				let padded_size = (last_entry_size as usize + self.block_size - target_data.len()) as u16;
				let size_loc = target_data.len()-last_entry_size as usize+4;
				target_data[size_loc] = padded_size.to_le_bytes()[0];
				target_data[size_loc+1] = padded_size.to_le_bytes()[1];
			}
			//write last block data (if there is any left)
			if new_last_data.len() > 0 {
				//println!("we have data to write to the last block");
				root.write_block(self, dir_blocks.len()-1, Some(&mut new_last_data))?;
			} else {
				root.write_block(self, dir_blocks.len()-1, None)?;
			}
		}
		
		//write new directory contents to root, dealloc blocks if necessary
		root.write_block(self, target_block.1, Some(&mut target_data))?;
		//println!("wrote to block {} of the inode",target_block.1);
		
		//decrement hard_links counter for target
		target.hard_links -= 1;
		//println!("target's links are now {}", target.hard_links);
		
        //recursively clear out directory
		if target.type_perm & TypePerm::DIRECTORY == TypePerm::DIRECTORY {
			//clear out children (would use read_dir_inode, but that holds the immutable reference to self while we remove)
	        let dir_size = target.size_low;
			let dir_blocks = target.get_all_blocks(&self);
	        let mut blocks_read = 0;
	        for block in dir_blocks {
				let entry_ptr = self.blocks[block as usize - self.block_offset].as_ptr();
			    let mut byte_offset: isize = 0;
		        while byte_offset < self.block_size.try_into().unwrap() && (blocks_read*self.block_size) as isize + byte_offset < dir_size as isize { 
		            let child = unsafe { 
			        	&*(entry_ptr.offset(byte_offset) as *const DirectoryEntry) 
			    	};
			        //assume that the directory size was aligned properly to the block
					if child.inode as usize != root_inode && child.inode as usize != target_inode {
						//don't recurse on those, just ignore them and "unlink" later by deallocing
						//println!("child is: {}, root is: {}, target is: {}", child.inode, root_inode,target_inode);
						self.remove(target_inode,child.inode as usize, &child.name.to_string())?;
					}
			        byte_offset += child.entry_size as isize;
			    }
			    blocks_read += 1;
	        }
	        target.hard_links -= 1; //for . directory (we will just dealloc the blocks)
	        root.hard_links -= 1; //for .. directory
	        //println!("after recursion, target's links are now {} and root's are {}", target.hard_links, root.hard_links);
		}
		
		
		//dealloc target inode and blocks if hard_links hits 0
		if target.hard_links == 0 {
			self.dealloc_inode(target_inode)?;
		}
		
		Ok(())
	}
	
	pub fn overwrite_file(&mut self, target_inode: usize, new_data: &mut Vec<u8>) -> std::io::Result<()>{
		//have to do the same thing again here... there's probbly a way to refactor this away 
		let target_group: usize = (target_inode - 1) / self.superblock.inodes_per_group as usize;
        let target_index: usize = (target_inode - 1) % self.superblock.inodes_per_group as usize;
        
        let target_inode_table_block = (self.block_groups[target_group].inode_table_block) as usize - self.block_offset;
        let target_inode_offset: isize = (target_index*std::mem::size_of::<Inode>()).try_into().unwrap();
        let target_inode_location = self.blocks[target_inode_table_block].as_ptr();
        // println!("in get_inode, block number of inode table {}", inode_table_block);
        let target = unsafe {
            &mut *(target_inode_location.offset(target_inode_offset) as *mut Inode)
        };
        
		let existing_blocks = target.get_all_blocks(self);
		let source_len = new_data.len();
		let source_blocks = (source_len+self.block_size-1)/self.block_size;
		//first truncate the file if necessary, so that the last block will adjust size properly
		for i in source_blocks..existing_blocks.len() {
			if let Err(e) = target.write_block(self, i, None){
				println!("unable to complete write, encountered error {}", e);
			}
		}
		//now write all of the blocks, appending when neccessary
		for i in 0..source_blocks {
			let start_of_block = i*self.block_size;
			let end_of_block = if i < source_blocks-1 {start_of_block+self.block_size} else {new_data.len()};
			if i < existing_blocks.len() {
				if let Err(e) = target.write_block(self, i, Some(&mut new_data[start_of_block..end_of_block])) {
					println!("failed import on block {} with error: {}", i, e);
					break;
				}
			} else {
				if let Err(e) = target.append_to_file(&mut new_data[start_of_block..end_of_block], self) {
					println!("failed import on block {} with error: {}", i, e);
					break;
				}
			}
		}
		Ok(())
	}

    pub fn read_dir_inode(&self, inode: usize) -> std::io::Result<Vec<(usize, &NulStr)>> {
        let mut ret = Vec::new();
        let root = self.get_inode(inode);
        //println!("in read_dir_inode, #{} : {:?}", inode, root);
        let dir_size = root.size_low;
		let dir_blocks = root.get_all_blocks(&self);
        let mut blocks_read = 0;
        for block in dir_blocks {
//			println!("readng block {} of the directory", blocks_read);
//			for i in 0..self.blocks[block as usize].len() {
//				print!("{} ",self.blocks[block as usize - self.block_offset][i]);
//			}
//			println!();
			//println!("following pointer to data block: {}", block);
			let entry_ptr = self.blocks[block as usize - self.block_offset].as_ptr();
		    let mut byte_offset: isize = 0;
	        while byte_offset < self.block_size.try_into().unwrap() && (blocks_read*self.block_size) as isize + byte_offset < dir_size as isize { 
	            let directory = unsafe { 
		        	&*(entry_ptr.offset(byte_offset) as *const DirectoryEntry) 
		    	};
		        //println!("found {:?}", directory);
		        //assume that the directory size was aligned properly to the block
				ret.push((directory.inode as usize, &directory.name));
		        byte_offset += directory.entry_size as isize;
		    }
		    blocks_read += 1;
        }
        Ok(ret)
    }
    
    pub fn read_ptr_block(&self, block: u32) -> Vec<u32> {
		if (block as usize) < self.block_offset {return Vec::new();}
		let mut blocks = Vec::new();
		let entry_ptr = self.blocks[block as usize - self.block_offset].as_ptr();
		let mut byte_offset: isize = 0;
		while byte_offset < self.block_size as isize {
			let ptr = unsafe { 
	        	&*(entry_ptr.offset(byte_offset) as *const u32)
	    	};
	    	if (*ptr as usize) > self.block_offset {
				blocks.push(*ptr);
			}
			byte_offset += 4;
		}
		blocks
	}
	
	pub fn read_double_ptr_block(&self, block: u32) -> Vec<u32>{
		if (block as usize) < self.block_offset {return Vec::new();}
		let more_blocks = self.read_ptr_block(block);
		let mut all_blocks = Vec::new();
		for indirect in more_blocks {
			all_blocks.append(&mut self.read_ptr_block(indirect));
		}
		all_blocks
	}
	
	pub fn read_triple_ptr_block(&self, block: u32) -> Vec<u32>{
		if (block as usize) < self.block_offset {return Vec::new();}
		let more_blocks = self.read_double_ptr_block(block);
		let mut all_blocks = Vec::new();
		for indirect in more_blocks {
			all_blocks.append(&mut self.read_ptr_block(indirect));
		}
		all_blocks
	}
	
	pub fn dir_entry_as_bytes(inode: u32, type_ind: TypeIndicator, name: &str) -> Vec<u8> {
		//TODO: 4-byte aligned entries
		let name_len = (name.len()+1) as u8;
		let entry_size = (name_len+8) as u16;
		let mut bytes = Vec::<u8>::new();
		//println!("entry size is {}, in bytes it's {} {}", entry_size, entry_size.to_le_bytes()[0],entry_size.to_le_bytes()[1]);
		bytes.extend_from_slice(&inode.to_le_bytes());
		bytes.extend_from_slice(&entry_size.to_le_bytes());
		bytes.push(name_len);
		bytes.push(type_ind as u8); //type_indicator not specified for now
		bytes.extend_from_slice(name.as_bytes());
		bytes.push(0x00u8); //nul terminator
		bytes
	}
	
	pub fn parse_path(&self, root_inode: usize, pathname: &str) -> std::io::Result<usize> {
		let last_name = match pathname.split('/').filter(|&x| !x.is_empty()).last() {
			Some(name) => name,
			None => ""
		};
        let path = pathname.split('/').filter(|&x| !x.is_empty());
        let mut parent_inode = root_inode;
       	for dir in path {
			let mut found = false;
			let children = match self.read_dir_inode(parent_inode) {
				Ok(dir_listing) => dir_listing,
				Err(_) => {
					return Err(std::io::Error::new(std::io::ErrorKind::Other,"unable to read directory"));
				}
			};
		    for child in &children {
		    	if child.1.to_string().eq(dir){
					if dir == last_name { //if this is the end of the path, return
						return Ok(child.0);
					}
					found = true;
					let new_inode = self.get_inode(child.0);
					//otherwise we need to read a directory
					if new_inode.type_perm & TypePerm::DIRECTORY == TypePerm::DIRECTORY {
			   			parent_inode = child.0;
		  			} else {
						return Err(std::io::Error::new(std::io::ErrorKind::Other,format!("{} is not a valid path", pathname)));
					}
		    	}
			}
			if !found {
		  		return Err(std::io::Error::new(std::io::ErrorKind::Other,format!("unable to locate {}", dir)));
		   	}
		}
		return Ok(root_inode);
	}
}

impl fmt::Debug for Inode<> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.size_low == 0 && self.size_high == 0 {
            f.debug_struct("").finish()
        } else {
            f.debug_struct("Inode")
            .field("type_perm", &self.type_perm)
            .field("size_low", &self.size_low)
            .field("direct_pointers", &self.direct_pointer)
            .field("indirect_pointer", &self.indirect_pointer)
            .finish()
        }
    }
}

impl Inode {
	pub fn get_all_blocks(&self, ext2: &Ext2) -> Vec<u32> {
		let file_size = self.file_size();
		let mut blocks = Vec::new();
		for ptr in self.direct_pointer{
			if ptr as usize > ext2.block_offset && blocks.len()*ext2.block_size < file_size as usize {
				blocks.push(ptr);
			}
		}
		for block in ext2.read_ptr_block(self.indirect_pointer){
			if blocks.len()*ext2.block_size < file_size as usize {
				blocks.push(block);
			}
		}
		for block in ext2.read_double_ptr_block(self.doubly_indirect){
			if blocks.len()*ext2.block_size < file_size as usize {
				blocks.push(block);
			}
		}
		for block in ext2.read_triple_ptr_block(self.triply_indirect){
			if blocks.len()*ext2.block_size < file_size as usize {
				blocks.push(block);
			}
		}
		
		blocks
	}
	
	pub fn block_space_left(&self,ext2: &Ext2) -> usize{
		let file_size = self.file_size();
		//add to the file size
		if file_size as usize % ext2.block_size == 0 {
			0
		} else { 
			ext2.block_size - (file_size as usize) % ext2.block_size
		}
	}
	
	pub fn get_block(&self, n: usize, ext2: &Ext2) -> u32 {
		//TODO: check against filesize
		if n < 12 {
			self.direct_pointer[n]
		} else if n < 12 + ext2.block_size/4 {
			ext2.read_ptr_block(self.indirect_pointer)[n-12]
		} else if n < 12 + ext2.block_size/4 + ext2.block_size*ext2.block_size/16 {
			ext2.read_double_ptr_block(self.doubly_indirect)[n-12 - ext2.block_size/4]
		} else {
			ext2.read_triple_ptr_block(self.triply_indirect)[n-12 - ext2.block_size/4 - ext2.block_size*ext2.block_size/16]
		}
	}
	
	pub fn set_block(&mut self, n: usize, block: u32, ext2: &Ext2) -> std::io::Result<()>{
		//out of bounds
		if n >= 12 + ext2.block_size/4 + ext2.block_size*ext2.block_size/16 + ext2.block_size*ext2.block_size*ext2.block_size/64 {
			return Err(std::io::Error::new(std::io::ErrorKind::Other,"error block index out of bounds"));
		}
		if n < 12 {
			self.direct_pointer[n] = block;
		} else if n < 12 + ext2.block_size/4 {
			ext2.read_ptr_block(self.indirect_pointer)[n-12] = block;
		} else if n < 12 + ext2.block_size/4 + ext2.block_size*ext2.block_size/16 {
			ext2.read_double_ptr_block(self.doubly_indirect)[n-12 - ext2.block_size/4] = block;
		} else {
			ext2.read_triple_ptr_block(self.triply_indirect)[n-12 - ext2.block_size/4 - ext2.block_size*ext2.block_size/16] = block;
		}
		Ok(())
	}
	
	//gets the last allocated block, if it exists
	pub fn get_last_block(&self, ext2: &Ext2) -> Option<u32> {
		let file_size = self.file_size();
		if file_size == 0 {
			//println!("The file size is 0",);
			return None;
		}
		
		let num_blocks = (file_size as usize - 1)/ext2.block_size;
		//println!("The last block of the file is {}, and is block {} of the file",self.get_block(num_blocks as usize,ext2),num_blocks);
		Some(self.get_block(num_blocks as usize,ext2))
	}
	
	fn to_new_block(&mut self, ext2: &mut Ext2) -> std::io::Result<u32> {
		//println!("inode only has {} space left",self.block_space_left(ext2));
		let mut file_size;
		if self.type_perm & TypePerm::DIRECTORY == TypePerm::DIRECTORY {
			file_size = self.size_low as u64;
		} else {
			file_size = (self.size_low as u64) + (self.size_high as u64)<<32;
		}
		//add to the file size
		file_size += self.block_space_left(ext2) as u64;
		self.size_low = file_size as u32;
		self.size_high = (file_size>>32) as u32;
		let num_blocks = (file_size as usize)/ext2.block_size;
		
		//alloc new block and add it
		let next_block = ext2.alloc_block()?;
		self.set_block(num_blocks, next_block, ext2)?;
		//println!("inode now has {} space left",self.block_space_left(ext2));
		//println!("inode moved to new block {}; it is block {} of the inode",next_block, num_blocks);
		Ok(next_block)
	}
	
	//need to make everything consistent with behaviour on block boundaries.  Decide when to add new blocks, how to check for existing blocks
	fn append_to_file(&mut self, bytes: &[u8], ext2: &mut Ext2) -> std::io::Result<usize> {
		let mut file_size = self.file_size();//check file size at beginning
		//println!("file size is {} before appending", file_size);
		
		let mut next_block;
		let mut byte_offset: usize = ext2.block_size - self.block_space_left(ext2);
		//block_space_left is accurate only if the file size is correct and to_new_block() hasn't just been called
		//use byte_offset within this method to keep track of progress through block
		if let Some(block) = self.get_last_block(ext2){
			next_block = block;
		} else {
			next_block = self.to_new_block(ext2)?;
			byte_offset = 0;
		}
//		println!("before");
//		for i in 0..ext2.blocks[next_block as usize - ext2.block_offset].len() {
//			print!("{} ",ext2.blocks[next_block as usize - ext2.block_offset][i]);
//		}
//		println!();
		//println!("appending to file on block: {}; space left to write is {}", next_block, self.block_space_left(ext2));
		let mut block_ptr = ext2.blocks[next_block as usize - ext2.block_offset].as_ptr();
		let mut block_bytes = unsafe {
			std::slice::from_raw_parts_mut(
		    	block_ptr as *mut u8,
		    	ext2.block_size,
		    )
		};
		
		let mut bytes_written = 0;
		
		for byte in bytes {
			//println!("writing byte {} of block {}; there are {} bytes remaining", byte_offset, next_block,ext2.block_size-byte_offset);
			if byte_offset == 1024 {
				next_block = self.to_new_block(ext2)?;
				block_ptr = ext2.blocks[next_block as usize - ext2.block_offset].as_ptr();
				block_bytes = unsafe {
					std::slice::from_raw_parts_mut(
			    		block_ptr as *mut u8,
			    		ext2.block_size,
			    	)
				};
				byte_offset = 0;
			}
			//println!("continued appending on new block {} with offset {}; {} space left in this block",next_block,byte_offset,ext2.block_size-byte_offset);
			block_bytes[byte_offset] = *byte;
			byte_offset += 1;
			bytes_written += 1;
			
			file_size += 1 as u64;
			self.size_low = file_size as u32;
			self.size_high = (file_size>>32) as u32;
		}
//		println!("after");
//		for i in 0..ext2.blocks[next_block as usize - ext2.block_offset].len() {
//			print!("{} ",ext2.blocks[next_block as usize - ext2.block_offset][i]);
//		}
//		println!();
		//println!("file size is {} after appending, using {} blocks", file_size, self.get_all_blocks(ext2).len());
		Ok(bytes_written)
	}
	
	fn write_block(&mut self, ext2: &mut Ext2, block_index: usize, new_data: Option<&mut [u8]>) -> std::io::Result<()> {
		let mut file_size = self.file_size();
		//println!("the file size before writing: {}", file_size);
		if let Some(data) = new_data{
			//if writing to the last block, should adjust file size
			if block_index == (file_size as usize - 1)/ext2.block_size {
				file_size = (block_index*ext2.block_size+data.len()) as u64;
				self.size_low = file_size as u32;
				self.size_high = (file_size>>32) as u32;
				if data.len() == 0 {
					//dealloc the block if we just wrote a blank block as the last block
					ext2.dealloc_block(self.get_block(block_index,ext2) as usize)?;
				}
			}
			
			//write the new data at block granularity
			//TODO: could maybe have offset?
			let block = self.get_block(block_index, ext2) as usize;
//			println!("before");
//			for i in 0..ext2.blocks[block].len() {
//				print!("{} ",ext2.blocks[block - ext2.block_offset][i]);
//			}
//			println!();
			for i in 0..data.len() {
				ext2.blocks[block - ext2.block_offset][i] = data[i];
			}
			//println!("the file size after writing: {}", file_size);
			//println!("we just wrote data of size {}", data.len());
//			println!("after");
//			for i in 0..ext2.blocks[block].len() {
//				print!("{} ",ext2.blocks[block - ext2.block_offset][i]);
//			}
//			println!();
		} else {
			//if None, dealloc the block
			ext2.dealloc_block(self.get_block(block_index, ext2) as usize)?;
			//then rearrange all the relevant pointers
			for i in block_index..=((file_size as usize - 1)/ext2.block_size) {
				self.set_block(i, self.get_block(i+1, ext2), ext2)?;
			}
			//and set filesize
			file_size -= ext2.block_size as u64;
			self.size_low = file_size as u32;
			self.size_high = (file_size>>32) as u32;
			//println!("the file size after deleting: {}", file_size);
		}
		Ok(())
	}
	
	pub fn file_size(&self) -> u64 {
		if self.type_perm & TypePerm::DIRECTORY == TypePerm::DIRECTORY {
			self.size_low as u64
		} else {
			(self.size_high as u64)<<32 | (self.size_low as u64)
		}
	}
	
}

fn main() -> Result<()> {
	//TODO read from file?
    let mut disk = include_bytes!("../myfsplusbeemovie.ext2").to_vec();
    let start_addr: usize = disk.as_mut_ptr() as usize;
    let mut ext2 = Ext2::new(&mut disk[..], start_addr);

    let mut current_working_inode:usize = 2;

    let mut rl = DefaultEditor::new()?;
    loop {
        // fetch the children of the current working directory
        let dirs = match ext2.read_dir_inode(current_working_inode) {
            Ok(dir_listing) => {
                dir_listing
            },
            Err(_) => {
                println!("unable to read cwd");
                break;
            }
        };

        let buffer = rl.readline(":> ");
        if let Ok(line) = buffer {
            if line.starts_with("ls") {
                // `ls` prints our cwd's children
                // supports arguments (print that directory's children instead)
                let elts: Vec<&str> = line.split(' ').collect();
                if elts.len() == 1 {//save neglible time by skipping parse_path (also don't have a pathname here)
     				for dir in &dirs {
                    	print!("{}\t", dir.1);
                    }
                    println!();
                } else {
					let target = elts[1];
					let target_inode = match ext2.parse_path(current_working_inode, target) {
						Ok(inode) => inode,
						Err(e) => {println!("{}", e);
				                0}
					};
					if target_inode != 0 && ext2.get_inode(target_inode).type_perm & TypePerm::DIRECTORY == TypePerm::DIRECTORY {
						let target_children = match ext2.read_dir_inode(target_inode) {
				            Ok(dir_listing) => {
				                dir_listing
				            },
				            Err(_) => {
				                println!("unable to read target");
				          		break;
				            }
				        };
						for dir in &target_children {
	                    	print!("{}\t", dir.1);
	                    }
	                    println!();
                    } else if target_inode != 0 {
						println!("{} is not a directory", target);
					}
				}
                
            } else if line.starts_with("cd") {
                // `cd` with no arguments, cd goes back to root
                // `cd dir_name` moves cwd to that directory
                let elts: Vec<&str> = line.split(' ').collect();
                if elts.len() == 1 {
     				current_working_inode = 2;
                } else {
                    // if the argument is a path, follow the path
                    // e.g., cd dir_1/dir_2 should move you down 2 directories
                    // deeper into dir_2
                    let to_dir = elts[1];
                    let new_inode = match ext2.parse_path(current_working_inode, to_dir) {
						Ok(inode) => inode,
						Err(e) => {println!("{}", e);
				                0}
					};
					if new_inode != 0 && ext2.get_inode(new_inode).type_perm & TypePerm::DIRECTORY == TypePerm::DIRECTORY {
		            	current_working_inode = new_inode;
	                } else {
						println!("can only cd into a directory");
					}
                }
            } else if line.starts_with("mkdir") {
                // `mkdir childname`
                // create a directory with the given name, add a link to cwd
                // TODO all commands with options should be robust against empty strings
                let elts: Vec<&str> = line.split(' ').collect();
                if elts.len() == 1 {
     				println!("must supply an argument to mkdir")
                } else {
					let options = &elts[1..elts.len()-1]; //in case I want to add other options, this is easier to work with
                    let pathname = elts[elts.len()-1];
                	
                    if options.contains(&"-p") {
						let mut found = false;
						let first_name = pathname.split('/').next().unwrap();
                    	for file in &dirs {
                        	if file.1.to_string().eq(first_name){
								found = true;
								println!("unable to make directory, {} already exists", first_name);
							}
                   	 	}
	                    if !found {
							let mut root_inode = current_working_inode;
							for name in pathname.split('/') {
								match ext2.add_dir(root_inode, name) {
									Ok(new_root_inode) => root_inode = new_root_inode,
									Err(err) => println!("unable to make directory {}, encountered error: {}",name,err),
								};
							}
	                    }
					} else if let Err(_) = ext2.parse_path(current_working_inode, pathname) {
						let path_vec: Vec<&str> = pathname.split('/').collect();
						let root_dir = path_vec[..path_vec.len()-1].join("/");
						let root_inode = match ext2.parse_path(current_working_inode, &root_dir) {
							Ok(inode) => inode,
							Err(e) => {println!("{}", e);
					                0}
						};
						if root_inode != 0 {
							if let Err(e) = ext2.add_dir(root_inode, path_vec[path_vec.len()-1]) {
								println!("unable to make directory {}, encountered error: {}",pathname,e);
							}
						}
					} else {
						println!("unable to make directory, {} already exists", pathname);
					}
                }
            } else if line.starts_with("cat") {
                // `cat filename`
                // print the contents of filename to stdout
                // if it's a directory, print a nice error
                // supports file paths
                let elts: Vec<&str> = line.split(' ').collect();
                if elts.len() == 1 {
     				println!("must supply an argument to cat")
                } else {
                    let filename = elts[1];
                    let target_inode = match ext2.parse_path(current_working_inode, filename) {
						Ok(inode) => inode,
						Err(e) => {println!("{}", e);
				                0}
					};
					if target_inode != 0 {
						let file_inode = ext2.get_inode(target_inode);
						if file_inode.type_perm & TypePerm::FILE == TypePerm::FILE {
							let file_size = file_inode.file_size();
							let blocks = file_inode.get_all_blocks(&ext2);
							let mut size_left = file_size as usize;
		                    for block_ptr in blocks {
								if size_left > 0 {
									let block_index = block_ptr as usize - ext2.block_offset;
									let contents = match std::str::from_utf8(ext2.blocks[block_index]){
										Ok(s) => s,
										Err(_) => "bad file",
									};
									if size_left < ext2.block_size {
										print!("{}", contents.split_at(size_left).0);
										size_left = 0;
									} else{
										print!("{}", contents);
										size_left -= contents.len();
									}
								}
							}
	                	} else {
							println!("unable to cat, {} is not a file", filename);
						}
					}
                }
            } else if line.starts_with("rm") {
                // `rm target`
                // unlink a file or empty directory
                // `rm -r target` to recursively empty a directory
                // get the target and check for -r
                //TODO: don't remove cwd
                let elts: Vec<&str> = line.split(' ').collect();
                if elts.len() == 1 {
     				println!("must supply an argument to rm")
                } else {
					let options = &elts[1..elts.len()-1]; //in case I want to add other options, this is easier to work with
                    let filename = elts[elts.len()-1];
                    let path_vec: Vec<&str> = filename.split('/').collect();
                    let parent_path = path_vec[..path_vec.len()-1].join("/");
                    let parent_inode_num = match ext2.parse_path(current_working_inode, &parent_path) {
						Ok(inode) => inode,
						Err(e) => {println!("unable to locate {}, encountered error: {}",parent_path,e);0}
					};
					let target_inode_num = match ext2.parse_path(current_working_inode, filename) {
						Ok(inode) => inode,
						Err(e) => {println!("unable to locate {}, encountered error: {}",filename,e);0}
					};
                    if parent_inode_num != 0 && target_inode_num != 0 {
	                    let target_inode = ext2.get_inode(target_inode_num);
	                    let is_dir = target_inode.type_perm & TypePerm::DIRECTORY == TypePerm::DIRECTORY;
	                    let is_file = target_inode.type_perm & TypePerm::FILE == TypePerm::FILE;
	                    if is_file || (is_dir && options.contains(&"-r")) {
							if let Err(err) = ext2.remove(parent_inode_num,target_inode_num,path_vec[path_vec.len()-1]) {
								println!("unable to remove {}, encountered error: {}",filename,err);
							}
						} else if is_dir {
							if let Ok(target_contents) = ext2.read_dir_inode(target_inode_num) {
								if target_contents.len() <= 2 {
									if let Err(err) = ext2.remove(parent_inode_num,target_inode_num,path_vec[path_vec.len()-1]) {
										println!("unable to remove {}, encountered error: {}",filename,err);
									}
								} else {
									println!("{} is not empty.",filename);
								}
							}
						} else {
							println!("{} is not a file or directory",filename);
						}
					}
                }
            } else if line.starts_with("mv") {
                // `mv filename target`
                // copies filename to target file
                //think about different filesystem destination -- check!!
                //just needs to link/unlink
                //TODO can you move a directory?
                let elts: Vec<&str> = line.split(' ').collect();
                if elts.len() < 3 {
     				println!("must supply two arguments to mv")
                } else {
                    let source_path = elts[1];
                    let source_path_vec: Vec<&str> = source_path.split('/').collect();
                    let link_path = elts[2];
                    let link_path_vec: Vec<&str> = link_path.split('/').collect();
                    let source_inode = match ext2.parse_path(current_working_inode,source_path){
						Ok(inode) => inode,
						Err(e) => {println!("{}",e);0},
					};
					let source_parent_path = source_path_vec[..source_path_vec.len()-1].join("/");
                    let source_parent = match ext2.parse_path(current_working_inode,&source_parent_path){
						Ok(inode) => inode,
						Err(e) => {println!("{}",e);0},
					};
					let source_name = source_path_vec[source_path_vec.len()-1];
                    let link_parent_path = link_path_vec[..link_path_vec.len()-1].join("/");
                    let link_parent = match ext2.parse_path(current_working_inode,&link_parent_path){
						Ok(inode) => inode,
						Err(e) => {println!("{}",e);0},
					};
                    let link_name;
					if link_path.ends_with('/') {
						link_name = source_path.split('/').last().unwrap();
					} else {
						link_name = link_path_vec[link_path_vec.len()-1];
					}
					
					if source_inode != 0 && link_parent != 0 && source_parent != 0 {
						if let Ok(_) = ext2.parse_path(link_parent,link_name){
							println!("{} already exists at the destination", link_name);
						} else if ext2.get_inode(source_inode).type_perm & TypePerm::DIRECTORY == TypePerm::DIRECTORY {
							println!("cannot move a directory");
						} else{
							if let Err(e) = ext2.link(source_inode,link_parent,link_name) {
								println!("unable to create destination link, encountered error {}", e);
							}
							if let Err(e) = ext2.remove(source_parent, source_inode, source_name) {
								println!("unable to remove source link, encountered error: {}",e);
							}
						}
					}
                }
            } else if line.starts_with("import") {
                // `import host_file target_name`
                // import a file from the host system as target_name
                let elts: Vec<&str> = line.split(' ').collect();
                if elts.len() < 3 {
     				println!("must supply two arguments to import")
                } else {
					//first find the tareget file (if it exists) or create a new one
                    let filename = elts[2];
                    let mut target_inode = match ext2.parse_path(current_working_inode, filename) {
						Ok(inode) => inode,
						Err(e) => 0,
					};
					//check that at least the parent exists, even if target doesn't
					let dest_path_vec: Vec<&str> = filename.split('/').collect();
					let dest_parent_path = dest_path_vec[..dest_path_vec.len()-1].join("/");
					let parent_inode = match ext2.parse_path(current_working_inode, &dest_parent_path) {
						Ok(inode) => inode,
						Err(_) => {println!("{}", e);
				                0}
					};
					while parent_inode != 0 {//TODO: find a better way to do this, it just feels nicer to use break if file doesn't exist
						let Ok(mut source_file) = File::open(format!("{}",elts[1])) else {
							println!("can't open file {}", elts[1]);
							break;
						};
						
						if target_inode == 0{
							//file doesn't exist yet - create it
							target_inode = match ext2.alloc_inode(){
								Ok(inode) => inode,
								Err(e) => {println!("unable to allocate new inode, encountered error {}", e);
								break;},
							};
							//link, set size_high, and set type_perm
							if let Err(e) = ext2.link(target_inode,parent_inode,dest_path_vec[dest_path_vec.len()-1]){
								println!("unable to link new inode, encountered error: {}", e);
							}
							let target = ext2.get_mut_inode(target_inode);
							target.type_perm = TypePerm::FILE;
							target.size_high = 0;
						}
						
						let mut read_data = vec![0;source_file.metadata()?.len() as usize];
						if let Err(e) = source_file.read_to_end(&mut read_data) {
							println!("unable to read {}, encountered error: {}", elts[1],e);
						} else {
							if let Err(e) = ext2.overwrite_file(target_inode,&mut read_data){
								println!("{}", e);
							}
						}
						
						break;
					}
                }
            } else if line.starts_with("export") {
                // `export filename host_target`
                // writes filename out to the host system at host_target
                // relative host filenames are determined from the repository directory
                let elts: Vec<&str> = line.split(' ').collect();
                if elts.len() < 3 {
     				println!("must supply two arguments to export")
                } else {
                    let filename = elts[1];
                    let target_inode = match ext2.parse_path(current_working_inode, filename) {
						Ok(inode) => inode,
						Err(e) => {println!("{}", e);
				                0}
					};
					if target_inode != 0 {
						let file_inode = ext2.get_inode(target_inode);
						if file_inode.type_perm & TypePerm::FILE == TypePerm::FILE {
							let mut dest_file = File::create(format!("{}",elts[2]))?;
							
							let file_size = file_inode.file_size();
							let blocks = file_inode.get_all_blocks(&ext2);
							let mut size_left = file_size as usize;
							let mut success = true;
		                    for block_ptr in blocks {
								if size_left > 0 {
									let block_index = block_ptr as usize - ext2.block_offset;
									if size_left < ext2.block_size {
										if let Err(e) = dest_file.write_all(ext2.blocks[block_index].split_at(size_left).0){
											println!("write failed on block {} with error {}", block_ptr, e);
											success = false;
											break;
										}
										size_left = 0;
									} else{
										if let Err(e) = dest_file.write_all(ext2.blocks[block_index]){
											println!("write failed on block {} with error {}", block_ptr, e);
											success = false;
											break;
										}
										size_left -= ext2.blocks[block_index].len();
									}
								}
							}
							dest_file.flush()?;
							if success{
								println!("export complete");
							}
	                	} else {
							println!("unable to export, {} is not a file", filename);
						}
					}
                }
            } else if line.starts_with("unmount") {
                // `unmount`
                // quits the filesystem and writes changes out to the device (file)
                //TODO: should this wait until every block is done to actually write them, somehow?
                let mut device_out = File::create("./myfsplusbeemovie.ext2")?;
                let boot_block = disk.split_at(EXT2_START_OF_SUPERBLOCK).0;
                if let Err(e) = device_out.write_all(boot_block) {
						println!("write failed on boot block with error {}", e);
				}
				let mut full_superblock = ext2.superblock.as_bytes().to_vec();
				let superblock_unused_bytes = disk.split_at(EXT2_END_OF_SUPERBLOCK).0.split_at(EXT2_START_OF_SUPERBLOCK+full_superblock.len()).1; //these are unused, so could just overwrite with resize e.g. row below, but this preserves file contents exactly
				//full_superblock.resize(EXT2_END_OF_SUPERBLOCK - EXT2_START_OF_SUPERBLOCK, 0u8);
				full_superblock.extend_from_slice(superblock_unused_bytes);
				if let Err(e) = device_out.write_all(full_superblock.as_slice()) {
						println!("write failed on superblock with error {}", e);
				}
				let mut group_descriptors = Vec::new();
				for descriptor in ext2.block_groups.iter() {
					group_descriptors.extend_from_slice(descriptor.as_bytes());
				}
				group_descriptors.resize(ext2.block_size,0u8);
				if let Err(e) = device_out.write_all(group_descriptors.as_slice()) {
					println!("write failed on block group descriptors with error {}", e);
				}
                for (i,block) in ext2.blocks.iter().enumerate() {
					if let Err(e) = device_out.write_all(block) {
						println!("write failed on block {} with error {}", i, e);
					}
				}
				device_out.flush()?;
                println!("unmount complete");
                break;
            } else if line.starts_with("mount") {
                // `mount host_filename mountpoint`
                // mount an ext2 filesystem over an existing empty directory
                //currently no plans to implement
                println!("mount not yet implemented");
            } else if line.starts_with("link") {
                // `link arg_1 arg_2`
                // create a hard link at arg2 pointing to arg_1
                // if arg2 ends in "/": use arg1 name
                // if arg2 is an existing directory name: 
                // do not create a hard link to a directory (prevent loops)
                // do not link to different filesystem
                let elts: Vec<&str> = line.split(' ').collect();
                if elts.len() < 3 {
     				println!("must supply two arguments to link")
                } else {
                    let source_path = elts[1];
                    let link_path = elts[2];
                    let link_path_vec: Vec<&str> = link_path.split('/').collect();
                    let source_inode = match ext2.parse_path(current_working_inode,source_path){
						Ok(inode) => inode,
						Err(e) => {println!("{}",e);0},
					};
                    let link_parent_path = link_path_vec[..link_path_vec.len()-1].join("/");
                    let link_parent = match ext2.parse_path(current_working_inode,&link_parent_path){
						Ok(inode) => inode,
						Err(e) => {println!("{}",e);0},
					};
                    let link_name;
					if link_path.ends_with('/') {
						link_name = source_path.split('/').last().unwrap();
					} else {
						link_name = link_path_vec[link_path_vec.len()-1];
					}
					
					if source_inode != 0 && link_parent != 0 {
						if let Ok(_) = ext2.parse_path(link_parent,link_name){
							println!("{} already exists at the destination", link_name);
						} else if ext2.get_inode(source_inode).type_perm & TypePerm::DIRECTORY == TypePerm::DIRECTORY {
							println!("cannot create a link to a directory");
						} else if let Err(e) = ext2.link(source_inode,link_parent,link_name) {
							println!("unable to create link, encountered error {}", e);
						}
					}
                }
                
            } else if line.starts_with("quit") || line.starts_with("exit") {
                break;
            }
        } else {
            println!("bye!");
            break;
        }
    }
    Ok(())
}
