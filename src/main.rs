#[macro_use]
pub mod helper;

use std::env;
use std::fs::{read_dir};
use std::path::{PathBuf};
use regex::Regex;

static mut GADGETS: Vec<usize> = vec![];
static mut CALLS: (u32, u32) = (0, 0);
static mut RETURNS: u32 = 0;
static mut DUPS: (u32, u32, u32, u32) = (0, 0, 0, 0);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GadgetType {
	Regular,
	CallPreceeded,
}
impl GadgetType {
	fn as_str(&self) -> &str {
		match self {
			GadgetType::Regular => "regular",
			GadgetType::CallPreceeded => "call-preceeded"
		}
	}
}

fn main() {
	let args: Vec<String> = env::args().collect();
	let target_path = match PathBuf::from(&args[2]).canonicalize() {
		Ok(x) => x,
		Err(e) => print_err_panic!("Specified target is not an existing file/dir! ('{}'): {}", args[2], e),
	};

	match args[1].as_str() {
		"size" => find_sizes(target_path),
		"call-gadgets" => find_gadgets(GadgetType::CallPreceeded, target_path),
		"all-gadgets" => find_gadgets(GadgetType::Regular, target_path),
		"fn-count" => count_functions(target_path),
		"insn-count" => count_instructions(target_path),
		_ => print_err!("No valid command specified!"),
	}
}

fn count_functions(target: PathBuf) {
	let (mut fn_total, mut popt1, mut popt2, mut popt3, mut bxlr) = 
		(0u32, 0u32, 0u32, 0u32, 0u32);

	if !target.is_dir() {
		print_err_panic!("Specified target must be a directory! ('{}')", target.to_str().unwrap());
	}
	for e in read_dir(&target).unwrap() {
		let entry = e.unwrap();
		let filep = entry.path();
		print_hint!("Looking for function count in {}", filep.to_str().unwrap());

		let nums = count_functions_in_bin(filep);
		fn_total += nums.0;
		popt1 += nums.1;
		popt2 += nums.2;
		popt3 += nums.3;
		bxlr += nums.4;
	}

	unsafe {
		print_info!(r"Found {} function symbols in binaries\n\t
			Found {} POP T1 returns + {} duplicates
			Found {} POP T2 returns + {} duplicates
			Found {} POP T3 returns + {} duplicates
			Found {} BX LR returns + {} duplicates", 
		fn_total, popt1, DUPS.0, popt2, DUPS.1, popt3, DUPS.2, bxlr, DUPS.3);
		print_info!("Found {} return instructions in total", RETURNS);
	}
}

fn count_functions_in_bin(target: PathBuf) -> (u32, u32, u32, u32, u32) {
	let fn_total: u32; 
	let (mut popt1, mut popt2, mut popt3, mut bxlr) = (0u32, 0u32, 0u32, 0u32);

	let mut cmd = std::process::Command::new("arm-none-eabi-readelf");
	cmd.args([ "-a", target.to_str().unwrap() ]);

	let elf_info = String::from_utf8(cmd.output().unwrap().stdout).unwrap();
	let mut elf_info_lines = elf_info.lines().collect::<Vec<&str>>();

	// HINT: DOES NOT COUNT WEAK FUNCTION SYMBOLS!!
	elf_info_lines = elf_info_lines.iter().filter(|x| (**x).contains("FUNC") && !(**x).contains("WEAK")).map(|s| *s).collect();
	fn_total = elf_info_lines.len() as u32;

	cmd = std::process::Command::new("arm-none-eabi-objdump");
	cmd.args([ "-d", target.to_str().unwrap() ]);

	let disassembly = String::from_utf8(cmd.output().unwrap().stdout).unwrap();
	let disasm_lines = disassembly.lines().collect::<Vec<&str>>();

	// fn_last_return contains the function name in which the last return occured
	// current_fn is the current function
	// In case there are two returns in one function, both are equal at a time
	let mut fn_last_return: String = String::new();
	let mut current_fn: String = String::new();

	let regex: Regex = Regex::new(r"[\w]{1,8} <([\w_]*)>:").unwrap();
	for l in disasm_lines.iter() {
		if regex.is_match(*l) {
			let caps = regex.captures_iter(*l).next().unwrap();
			current_fn = String::from(&caps[1]);
		}

		if (*l).contains("pop") && (*l).contains("pc") {
			if current_fn != fn_last_return {
				fn_last_return = current_fn.clone();
				popt1 += 1;
			} else {
				unsafe { DUPS.0 += 1; }
			}
			unsafe { RETURNS += 1; }
		} else if (*l).contains("ldmia.w") && (*l).contains("sp!") && (*l).contains("pc") {
			if current_fn != fn_last_return {
				fn_last_return = current_fn.clone();
				popt2 += 1;
			} else {
				unsafe { DUPS.1 += 1; }
			}
			unsafe { RETURNS += 1; }
		} else if (*l).contains("ldr.w") && (*l).contains("pc") && (*l).contains("[sp]") {
			if current_fn != fn_last_return {
				fn_last_return = current_fn.clone();
				popt3 += 1;
			} else {
				unsafe { DUPS.2 += 1; }
			}
			unsafe { RETURNS += 1; }
		} else if (*l).contains("bx	lr") {
			if current_fn != fn_last_return {
				fn_last_return = current_fn.clone();
				bxlr += 1;
			} else {
				unsafe { DUPS.3 += 1; }
			}
			unsafe { RETURNS += 1; }
		}
	}
	
	(fn_total, popt1, popt2, popt3, bxlr)
}

fn count_instructions(target: PathBuf) {
	let mut instr_count: u32 = 0;
	for e in read_dir(&target).unwrap() {
		let entry = e.unwrap();
		let filep = entry.path();
		print_hint!("Looking for instruction count in {}", filep.to_str().unwrap());
		instr_count += count_instructions_in_bin(filep);
	}

	print_info!("Found {} instructions in binaries", instr_count);
}

fn count_instructions_in_bin(target: PathBuf) -> u32 {
	let mut cmd = std::process::Command::new("arm-none-eabi-objdump");
	cmd.args([ "-d", target.to_str().unwrap() ]);

	let disassembly = String::from_utf8(cmd.output().unwrap().stdout).unwrap();
	let mut disasm_lines = disassembly.lines().collect::<Vec<&str>>();

	let reg1: Regex = Regex::new(r"\t[\w]{2} [\w]{2} [\w]{2} [\w]{2}").unwrap();
	let reg2: Regex = Regex::new(r"[\w]{1,8} <[\w_]*>:").unwrap();
	let reg3: Regex = Regex::new(r"\t[\w]{8} [\w]{8}").unwrap();
	let reg4: Regex = Regex::new(r"\t[\w]{8}[ ]{2,}").unwrap();
	disasm_lines = disasm_lines.iter().filter(|x| {
		if **x == "" || **x == "\n" || **x == "\r\n" ||
			(**x).contains("Disassembly") || (**x).contains(".word") || (**x).contains(".byte") ||
			(**x).contains(".short") || (**x).contains("...") || (**x).contains("file format")
		{
			return false;
		}

		if reg1.is_match(**x) || reg2.is_match(**x) || reg3.is_match(**x) || reg4.is_match(**x) {
			return false;
		}

		true
	}).map(|s| *s).collect();

	disasm_lines.len() as u32
}

fn find_gadgets(gadget_type: GadgetType, target: PathBuf) {
	for e in read_dir(&target).unwrap() {
		let entry = e.unwrap();
		let file_path = entry.path();
		print_hint!("Looking for {} gadgets in {}", gadget_type.as_str(), file_path.to_str().unwrap());
		
		match gadget_type {
			GadgetType::Regular => find_regular_gadgets(&file_path),
			GadgetType::CallPreceeded => find_call_gadgets(&file_path),
		}
	}

	// display results
	for i in 0..=10_usize {
		let filtered_gadgets: Vec<usize>;
		unsafe { 
			filtered_gadgets = match gadget_type {
				GadgetType::Regular => GADGETS.iter().filter(|x| **x >= i).map(|s| *s).collect(),
				GadgetType::CallPreceeded => GADGETS.iter().filter(|x| **x == i).map(|s| *s).collect(),
			}
		}

		print_info!("Found {} {} gadgets with len {}", filtered_gadgets.len(), gadget_type.as_str(), i);
	}
	if gadget_type == GadgetType::CallPreceeded {
		unsafe { print_info!("Found total of {} BL and {} BLX calls in binaries", CALLS.0, CALLS.1); }
	}
}

fn find_regular_gadgets(target: &PathBuf) {
	let mut cmd = std::process::Command::new("arm-none-eabi-objdump");
	cmd.args(["-d", target.to_str().unwrap() ]);

	let disassembly = String::from_utf8(cmd.output().unwrap().stdout).unwrap();
	let disasm_lines = disassembly.lines().collect::<Vec<&str>>();
	let mut dist: usize = 0;
	for idx in 0..disasm_lines.len() {
		if disasm_lines[idx].contains("	pop") && disasm_lines[idx].contains("pc") {
			unsafe { GADGETS.push(dist); RETURNS += 1; }
			dist = 0;
			continue;
		} else if disasm_lines[idx].contains("	ldmia.w") && disasm_lines[idx].contains("sp!") && disasm_lines[idx].contains("pc") {
			unsafe { GADGETS.push(dist); RETURNS += 1; }
			dist = 0;
			continue;
		} else if disasm_lines[idx].contains("	ldr.w") && disasm_lines[idx].contains("pc") && disasm_lines[idx].contains("sp") {
			unsafe { GADGETS.push(dist); RETURNS += 1; }
			dist = 0;
			continue;
		} else if disasm_lines[idx].contains("	bx	lr") {
			unsafe { GADGETS.push(dist); RETURNS += 1; }
			dist = 0;
			continue;
		}

		dist += 1;
	}
}

fn find_call_gadgets(target: &PathBuf) {
	let mut cmd = std::process::Command::new("arm-none-eabi-objdump");
	cmd.args([ "-d", target.to_str().unwrap() ]);
	let cmd_res = cmd.output().unwrap();

	let disassembly = String::from_utf8(cmd_res.stdout).unwrap();
	let disasm_lines = disassembly.lines().collect::<Vec<&str>>();
	for idx in 0..disasm_lines.len() {
		if disasm_lines[idx].contains("	bl	") || disasm_lines[idx].contains("	bl ") {
			for i in 1_usize..=11_usize {
				if idx + i >= disasm_lines.len() {
					break;
				}

				if disasm_lines[idx + i].contains("pop") || 
					(disasm_lines[idx + i].contains("ldmia.w") && disasm_lines[idx + i].contains("pc")) ||
					(disasm_lines[idx + i].contains("ldr") && disasm_lines[idx + i].contains("pc") && disasm_lines[idx + i].contains("sp")) ||
					(disasm_lines[idx + i].contains("bx") && disasm_lines[idx + i].contains("lr") && disasm_lines[idx + i].contains("4770"))
				{
					print_hint!("Found gadget in line {} ('{}') with len {}", idx, disasm_lines[idx], i);
					unsafe { GADGETS.push(i - 1); }
					break;
				}
				
			}
			unsafe { CALLS.0 += 1; }
		} else if disasm_lines[idx].contains("	blx	") || disasm_lines[idx].contains("	blx ") {
			for i in 1_usize..=11_usize {
				if idx + i >= disasm_lines.len() {
					break;
				}

				if disasm_lines[idx + i].contains("pop") || 
					(disasm_lines[idx + i].contains("ldmia.w") && disasm_lines[idx + i].contains("pc")) ||
					(disasm_lines[idx + i].contains("ldr") && disasm_lines[idx + i].contains("pc") && disasm_lines[idx + i].contains("sp")) ||
					(disasm_lines[idx + i].contains("bx") && disasm_lines[idx + i].contains("lr") && disasm_lines[idx + i].contains("4770")) 
				{
					print_hint!("Found gadget in line {} ('{}') with len {}", idx, disasm_lines[idx], i);
					unsafe { GADGETS.push(i - 1); }
					break;
				}
			}
			unsafe { CALLS.1 += 1; }
		}
	}
}

fn find_sizes(target: PathBuf) {
	const CMD: &str = "arm-none-eabi-readelf";
	let mut overall_size: u64 = 0;
	let mut file_size: u64 = 0;
	for e in read_dir(&target).unwrap() {
		let file_entry = e.unwrap();
		file_size += file_entry.metadata().unwrap().len();

		let mut cmd = std::process::Command::new(CMD);
		cmd.args([ "-a", file_entry.path().to_str().unwrap() ]);
		
		let output = String::from_utf8(cmd.output().unwrap().stdout).unwrap();
		let lines = output.lines().collect::<Vec<&str>>();

		let reg = Regex::new(r"\.text.*PROGBITS[\s]+([\d]+)[\s]{1}([\w]+)[\s]{1}([\w]+)").unwrap();
		for l in lines.iter() {
			if reg.is_match(*l) {
				let caps = reg.captures_iter(*l).next().unwrap();
				let size_num: u64 = hex_str_to_uint(&caps[3]);
				print_hint!("Size: '{}' - {}", &caps[3], size_num);
				overall_size += size_num;
			}
		}
	}

	print_info!("Size of all .text sections: {}", overall_size);
	print_info!("Size of all files: {}", file_size);
}

fn hex_str_to_uint(pstr: &str) -> u64 {
	let mut chars: Vec<u8> = pstr.bytes().collect();
	chars.reverse();

	let mut num: u64 = 0;
	let mut idx: u32 = 0;
	const RADIX: u64 = 16;
	for c in chars.iter() {
	    if *c == b'0' || *c == b'x' {
	        idx += 1;
	        continue;
	    }
	
	    let cnum: u64 = match c {
	        t if (0x30..=0x39).contains(t) => (*t - 0x30) as u64,
	        t if (0x41..=0x46).contains(t) => (*t - 0x41) as u64,
			t if (0x61..=0x7a).contains(t) => (*t - 0x61) as u64,
	        t => panic!("Invalid character: '{}' !", *t),
	    };
		num += cnum * RADIX.pow(idx);
		idx += 1;
	}

	num
}

#[allow(unused)]
fn dec_str_to_uint(pstr: &str) -> i64{
	let sign: i64;
	let mut chars: Vec<u8> = pstr.bytes().collect();
	match chars[0] {
	    0x2d => sign = -1,
	    _ => sign = 1,
	}
	chars.reverse();
	chars.pop();

	let mut num: i64 = 0;
	let mut idx: u32 = 0;
	const RADIX: i64 = 10;
	for c in chars.iter() {
		let cnum: i64 = match c {
			t if (0x30..=0x39).contains(t) => (*t - 0x30) as i64,
			_ => panic!("Invalid character")
		};
		num += cnum * RADIX.pow(idx);
		idx += 1;
	}

	num * sign
}