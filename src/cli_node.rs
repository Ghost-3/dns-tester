//! Граничный узел CLI: чтение аргументов процесса ОС и вывод текста в стандартный поток.

pub struct CliNode;

impl CliNode {
    pub fn read_raw_args(&self) -> Box<[String]> {
        // Пропускаем нулевой аргумент (путь к бинарнику ОС)
        std::env::args()
            .skip(1)
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }

    pub fn print(&self, text: &str) {
        println!("{text}");
    }
}
