using System;

class Program
{
    static void Main(string[] args)
    {
        FileEncryptor2 encryptor = new FileEncryptor2();

        Console.WriteLine("Selecione uma opção:");
        Console.WriteLine("1 - Criptografar arquivo");
        Console.WriteLine("2 - Descriptografar arquivo");
        string escolha = Console.ReadLine();

        if (escolha == "1")
        {
            Console.Write("Informe o caminho do arquivo de entrada: ");
            string inputFile = Console.ReadLine();

            Console.Write("Informe o caminho do arquivo de saída criptografado: ");
            string outputFile = Console.ReadLine();

            encryptor.EncryptFile(inputFile, outputFile);

            Console.WriteLine("Arquivo criptografado com sucesso.");
        }
        else if (escolha == "2")
        {
            Console.Write("Informe o caminho do arquivo criptografado de entrada: ");
            string inputFile = Console.ReadLine();

            Console.Write("Informe o caminho do arquivo de saída descriptografado: ");
            string outputFile = Console.ReadLine();

            encryptor.DecryptFile(inputFile, outputFile);

            Console.WriteLine("Arquivo descriptografado com sucesso.");
        }
        else
        {
            Console.WriteLine("Escolha inválida. Encerrando o programa.");
        }
    }
}
