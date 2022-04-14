
macro_rules! print_msg {
	($color:literal, $code:expr, $x:literal) => {
		println!("{}[ {} ]{}{}\x1b[0m", $color, $code, space_fill!($code.len() + 4, 10), $x)
	};
	($color:literal, $code:expr, $x:literal, $($y:expr), *) => {
		println!("{}[ {} ]{}{}\x1b[0m", $color, $code, space_fill!($code.len() + 4, 10), format!($x, $($y), *))
	};
}
//#[macro_export]
macro_rules! print_info {
	($($x:tt) *) => {
		print_msg!("\x1b[32m", "INFO", $($x)*);
	};
}
//#[macro_export]
macro_rules! print_hint {
	($($x:tt) *) => {
		print_msg!("\x1b[33m", "HINT", $($x)*)
	};
}/*
//#[macro_export]
macro_rules! print_skip {
	($($x:tt) *) => {
		print_msg!("\x1b[33m", "SKIP", $($x)*)
	};
}*/
//#[macro_export]
macro_rules! print_err {
	($($x:tt) *) => {
		print_msg!("\x1b[31m", "FAIL", $($x)*)
	};
}
macro_rules! print_err_panic {
	($($x:tt) *) => {{
		print_msg!("\x1b[31m", "FAIL", $($x)*);
		panic!();
	}};
}

//#[macro_export]
macro_rules! space_fill {
	($len:expr, $til:literal) => {
		if $len <= $til {
			" ".repeat($til - $len)
		} else {
			" ".repeat($len % $til)
		}
	};
}