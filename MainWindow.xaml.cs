using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Windows;

namespace BuildIsoEncrypt
{
    public partial class MainWindow : Window
    {
        private const int SaltSize = 32;
        private const int KeySize = 32;
        private const int Iterations = 300_000;
        private const int RecoveryKeyCount = 10;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void Browse_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == true)
                FilePathBox.Text = ofd.FileName;
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            if (!ValidateInputs()) return;

            try
            {
                string input = FilePathBox.Text;
                string output = input + ".enc";

                var recoveryKeys = EncryptFile(input, output, PasswordBox.Password);

                SecureDelete(input);

                FilePathBox.Text = output;
                MessageBox.Show("File encrypted and original securely removed.", "BuildIsoEncrypt");

                ShowRecoveryKeysDialog(recoveryKeys);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Encryption error: " + ex.Message, "BuildIsoEncrypt");
            }
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            if (!ValidateInputs()) return;

            try
            {
                string input = FilePathBox.Text;

                if (!input.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
                    throw new Exception("Encrypted file must end with .enc");

                string output = input.Substring(0, input.Length - 4);

                DecryptFile(input, output, PasswordBox.Password);

                SecureDelete(input);

                FilePathBox.Text = output;
                MessageBox.Show("File decrypted and encrypted file securely removed.", "BuildIsoEncrypt");
            }
            catch (Exception ex)
            {
                MessageBox.Show("Decryption error: " + ex.Message, "BuildIsoEncrypt");
            }
        }

        private bool ValidateInputs()
        {
            if (string.IsNullOrWhiteSpace(FilePathBox.Text) || !File.Exists(FilePathBox.Text))
            {
                MessageBox.Show("Invalid file.", "BuildIsoEncrypt");
                return false;
            }

            if (string.IsNullOrWhiteSpace(PasswordBox.Password))
            {
                MessageBox.Show("Password cannot be empty.", "BuildIsoEncrypt");
                return false;
            }

            return true;
        }

        /// <summary>
        /// File format:
        /// [saltPwd(32)] [ivPwd(16)] [encDataKeyWithPwd(48)]
        /// For each of 10 recovery keys:
        ///   [saltRec(32)] [ivRec(16)] [encDataKeyWithRec(48)]
        /// [ivData(16)] [ciphertext...]
        /// </summary>
        private List<string> EncryptFile(string inputPath, string outputPath, string password)
        {
            byte[] dataKey = RandomNumberGenerator.GetBytes(KeySize);

            byte[] saltPwd = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] ivPwd = RandomNumberGenerator.GetBytes(16);

            byte[] keyPwd = Rfc2898DeriveBytes.Pbkdf2(
                password,
                saltPwd,
                Iterations,
                HashAlgorithmName.SHA256,
                KeySize
            );

            byte[] encDataKeyWithPwd = EncryptSmallBlock(dataKey, keyPwd, ivPwd);

            var recoveryKeys = new List<string>();
            var saltRecList = new List<byte[]>();
            var ivRecList = new List<byte[]>();
            var encDataKeyRecList = new List<byte[]>();

            for (int i = 0; i < RecoveryKeyCount; i++)
            {
                string recoveryKey = Guid.NewGuid().ToString();
                recoveryKeys.Add(recoveryKey);

                byte[] saltRec = RandomNumberGenerator.GetBytes(SaltSize);
                byte[] ivRec = RandomNumberGenerator.GetBytes(16);

                byte[] keyRec = Rfc2898DeriveBytes.Pbkdf2(
                    recoveryKey,
                    saltRec,
                    Iterations,
                    HashAlgorithmName.SHA256,
                    KeySize
                );

                byte[] encDataKeyWithRec = EncryptSmallBlock(dataKey, keyRec, ivRec);

                saltRecList.Add(saltRec);
                ivRecList.Add(ivRec);
                encDataKeyRecList.Add(encDataKeyWithRec);
            }

            byte[] ivData = RandomNumberGenerator.GetBytes(16);

            using var fsInput = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
            using var fsOutput = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
            using var bw = new BinaryWriter(fsOutput);

            bw.Write(saltPwd);
            bw.Write(ivPwd);
            bw.Write(encDataKeyWithPwd);

            for (int i = 0; i < RecoveryKeyCount; i++)
            {
                bw.Write(saltRecList[i]);
                bw.Write(ivRecList[i]);
                bw.Write(encDataKeyRecList[i]);
            }

            bw.Write(ivData);

            using var aesData = Aes.Create();
            aesData.KeySize = 256;
            aesData.BlockSize = 128;
            aesData.Mode = CipherMode.CBC;
            aesData.Padding = PaddingMode.PKCS7;
            aesData.Key = dataKey;
            aesData.IV = ivData;

            using var crypto = new CryptoStream(fsOutput, aesData.CreateEncryptor(), CryptoStreamMode.Write);
            fsInput.CopyTo(crypto);

            return recoveryKeys;
        }

        private void DecryptFile(string inputPath, string outputPath, string passwordOrRecovery)
        {
            using var fsInput = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
            using var br = new BinaryReader(fsInput);

            byte[] saltPwd = br.ReadBytes(SaltSize);
            byte[] ivPwd = br.ReadBytes(16);
            byte[] encDataKeyWithPwd = br.ReadBytes(48);

            var saltRecList = new List<byte[]>();
            var ivRecList = new List<byte[]>();
            var encDataKeyRecList = new List<byte[]>();

            for (int i = 0; i < RecoveryKeyCount; i++)
            {
                saltRecList.Add(br.ReadBytes(SaltSize));
                ivRecList.Add(br.ReadBytes(16));
                encDataKeyRecList.Add(br.ReadBytes(48));
            }

            byte[] ivData = br.ReadBytes(16);

            byte[] dataKey = null;

            try
            {
                byte[] keyPwd = Rfc2898DeriveBytes.Pbkdf2(
                    passwordOrRecovery,
                    saltPwd,
                    Iterations,
                    HashAlgorithmName.SHA256,
                    KeySize
                );

                dataKey = DecryptSmallBlock(encDataKeyWithPwd, keyPwd, ivPwd);
            }
            catch (CryptographicException)
            {
                dataKey = null;
            }

            if (dataKey == null)
            {
                for (int i = 0; i < RecoveryKeyCount && dataKey == null; i++)
                {
                    try
                    {
                        byte[] keyRec = Rfc2898DeriveBytes.Pbkdf2(
                            passwordOrRecovery,
                            saltRecList[i],
                            Iterations,
                            HashAlgorithmName.SHA256,
                            KeySize
                        );

                        dataKey = DecryptSmallBlock(encDataKeyRecList[i], keyRec, ivRecList[i]);
                    }
                    catch (CryptographicException)
                    {
                        dataKey = null;
                    }
                }
            }

            if (dataKey == null)
                throw new Exception("Invalid password or recovery key.");

            using var fsOutput = new FileStream(outputPath, FileMode.Create, FileAccess.Write);

            using var aesData = Aes.Create();
            aesData.KeySize = 256;
            aesData.BlockSize = 128;
            aesData.Mode = CipherMode.CBC;
            aesData.Padding = PaddingMode.PKCS7;
            aesData.Key = dataKey;
            aesData.IV = ivData;

            using var crypto = new CryptoStream(fsInput, aesData.CreateDecryptor(), CryptoStreamMode.Read);
            crypto.CopyTo(fsOutput);
        }

        private byte[] EncryptSmallBlock(byte[] data, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;

            using var ms = new MemoryStream();
            using (var crypto = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                crypto.Write(data, 0, data.Length);
            }
            return ms.ToArray();
        }

        private byte[] DecryptSmallBlock(byte[] data, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;

            using var ms = new MemoryStream(data);
            using var crypto = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var result = new MemoryStream();
            crypto.CopyTo(result);
            return result.ToArray();
        }

        private void SecureDelete(string path)
        {
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists)
                    return;

                long length = fi.Length;
                byte[] buffer = new byte[8192];

                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Write))
                {
                    long remaining = length;
                    while (remaining > 0)
                    {
                        RandomNumberGenerator.Fill(buffer);
                        int toWrite = remaining > buffer.Length ? buffer.Length : (int)remaining;
                        fs.Write(buffer, 0, toWrite);
                        remaining -= toWrite;
                    }
                    fs.Flush(true);
                }

                File.Delete(path);
            }
            catch
            {
                // best effort, do not crash
            }
        }

        private void ShowRecoveryKeysDialog(List<string> recoveryKeys)
        {
            string content = string.Join(Environment.NewLine, recoveryKeys);

            var result = MessageBox.Show(
                "Here are your 10 recovery keys (UUID format):\n\n" +
                content +
                "\n\nDo you want to save them to a file?",
                "Recovery keys",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);

            if (result == MessageBoxResult.Yes)
            {
                var sfd = new SaveFileDialog
                {
                    Title = "Save recovery keys",
                    Filter = "Text file (*.txt)|*.txt|All files (*.*)|*.*",
                    FileName = "BuildIsoEncrypt_RecoveryKeys.txt"
                };

                if (sfd.ShowDialog() == true)
                {
                    File.WriteAllText(sfd.FileName, content);
                    MessageBox.Show("Recovery keys saved.", "BuildIsoEncrypt");
                }
            }
            else
            {
                var confirm = MessageBox.Show(
                    "Are you sure to cancel saving recovery keys?\n" +
                    "If you lose both your password and these keys, decryption will be impossible.",
                    "Confirm cancel",
                    MessageBoxButton.OKCancel,
                    MessageBoxImage.Warning);

                if (confirm == MessageBoxResult.Cancel)
                {
                    ShowRecoveryKeysDialog(recoveryKeys);
                }
            }
        }

        private void Window_DragOver(object sender, DragEventArgs e)
        {
            e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop)
                ? DragDropEffects.Copy
                : DragDropEffects.None;

            e.Handled = true;
        }

        private void Window_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                var files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files.Any())
                    FilePathBox.Text = files[0];
            }
        }
    }
}
