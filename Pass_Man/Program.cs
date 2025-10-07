using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;
using System.Drawing;
using System.Globalization;
using System.Threading;

namespace AuthManagerApp
{
    #region PART 0: DATA MODELS & SETTINGS
    //================================================================================
    // PART 0: DATA MODELS & SETTINGS
    // Класи для конфігурації, записів паролів та налаштувань програми.
    //================================================================================
    public class AuthConfig
    {
        public string PasswordSalt { get; set; }
        public string PasswordHash { get; set; }
        public string RecoverySalt { get; set; }
        public string RecoveryHash { get; set; }
    }

    public class PasswordEntry
    {
        public Guid Id { get; set; }
        public string AccountName { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string Notes { get; set; }
    }

    public class AppSettings
    {
        public string Language { get; set; } = "uk-UA";
        public string VaultPath { get; set; } = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "vault.dat");
        public string Theme { get; set; } = "Dark"; // "Dark" or "Light"
        public string AccentColor { get; set; } = "#007BFF"; // Hex color
    }

    public static class SettingsManager
    {
        private static readonly string SettingsFile = "settings.json";
        public static AppSettings Load()
        {
            if (!File.Exists(SettingsFile)) return new AppSettings();
            try
            {
                string json = File.ReadAllText(SettingsFile);
                return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
            }
            catch { return new AppSettings(); }
        }
        public static void Save(AppSettings settings)
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(settings, options);
            File.WriteAllText(SettingsFile, json);
        }
    }
    #endregion

    #region PART 1: SERVICES (Crypto, Localization, Theme)
    //================================================================================
    // PART 1: SERVICES (CRYPTO, LOCALIZATION, THEME)
    // Допоміжні класи для криптографії, керування мовою та темами.
    //================================================================================
    public static class CryptoService
    {
        private const int KeySize = 32, IvSize = 16, Iterations = 480000;

        public static byte[] DeriveKey(string password, byte[] salt)
        {
            using (var kdf = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
            {
                return kdf.GetBytes(KeySize);
            }
        }

        public static string Encrypt(string plainText, byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                byte[] iv = aes.IV;
                using (var encryptor = aes.CreateEncryptor(aes.Key, iv))
                using (var ms = new MemoryStream())
                {
                    ms.Write(iv, 0, iv.Length);
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        public static string Decrypt(string cipherTextWithIvBase64, byte[] key)
        {
            byte[] cipherTextWithIv = Convert.FromBase64String(cipherTextWithIvBase64);
            byte[] iv = new byte[IvSize];
            Array.Copy(cipherTextWithIv, 0, iv, 0, iv.Length);
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream(cipherTextWithIv, IvSize, cipherTextWithIv.Length - IvSize))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }
    }

    public static class LocalizationService
    {
        private static Dictionary<string, string> _currentDict;
        private static readonly Dictionary<string, Dictionary<string, string>> AllStrings = new Dictionary<string, Dictionary<string, string>>
        {
            ["uk-UA"] = new Dictionary<string, string> {
                {"Login", "Вхід"}, {"Setup", "Налаштування"}, {"Recovery", "Відновлення"}, {"PasswordManager", "Менеджер Паролів"}, {"Save", "Зберегти"},
                {"InitialSetup", "Початкове налаштування"}, {"NewPassword", "Новий пароль"}, {"ConfirmPassword", "Підтвердіть пароль"}, {"CreateRecoveryKey", "Створити файл-ключ відновлення"},
                {"FinishSetup", "Завершити налаштування"}, {"EnterMasterPassword", "Введіть майстер-пароль"}, {"RecoverAccess", "Відновити доступ"}, {"ChooseKeyFile", "Обрати файл-ключ"},
                {"FileNotChosen", "Файл не обрано"}, {"ChangePassword", "Змінити пароль"}, {"BackToLogin", "Назад до входу"}, {"EntryDetails", "Деталі запису"},
                {"Title", "Назва:"}, {"LoginEmail", "Логін/Email:"}, {"Password", "Пароль:"}, {"Notes", "Нотатки:"}, {"AddNew", "Додати новий"},
                {"Delete", "Видалити"}, {"Logout", "Вийти"}, {"Settings", "Налаштування"}, {"Language", "Мова"}, {"VaultPath", "Шлях до сховища"},
                {"Theme", "Тема"}, {"AccentColor", "Колір акценту"}, {"Light", "Світла"}, {"Dark", "Темна"}, {"Browse", "Огляд..."}, {"Cancel", "Скасувати"},
                {"PasswordCannotBeEmpty", "Пароль не може бути порожнім."}, {"PasswordsDoNotMatch", "Паролі не збігаються."}, {"Error", "Помилка"},
                {"SetupError", "Помилка налаштування"}, {"Success", "Успіх"}, {"Info", "Інформація"}, {"RecoveryKeyCreationCancelled", "Створення файлу-ключа скасовано."},
                {"LoginError", "Помилка входу"}, {"VaultLoadError", "Помилка завантаження сховища"}, {"PleaseEnterPassword", "Будь ласка, введіть пароль."},
                {"AccountNameCannotBeEmpty", "Назва акаунту не може бути порожньою."}, {"Saved", "Збережено!"}, {"ConfirmDelete", "Підтвердження"},
                {"ConfirmDeleteMessage", "Ви впевнені, що хочете видалити запис '{0}'?"}, {"VaultDecryptionError", "Не вдалося розшифрувати сховище. Можливо, невірний пароль або файл пошкоджено."},
                {"RecoveryPasswordResetWarning", "Пароль успішно змінено! УВАГА: Старе сховище паролів було видалено."}, {"NewAccount", "Новий акаунт"},
                {"SaveKeyFileTitle", "Зберегти файл-ключ"}, {"SelectKeyFileTitle", "Оберіть файл-ключ"}, {"SettingsApplied", "Налаштування застосовано. Деякі зміни потребують перезапуску."},
                {"ChooseKeyFileError", "Будь ласка, оберіть файл-ключ."}, {"PasswordsEmptyOrMismatch", "Паролі порожні або не збігаються."}
            },
            ["en-US"] = new Dictionary<string, string> {
                {"Login", "Login"}, {"Setup", "Setup"}, {"Recovery", "Recovery"}, {"PasswordManager", "Password Manager"}, {"Save", "Save"},
                {"InitialSetup", "Initial Setup"}, {"NewPassword", "New Password"}, {"ConfirmPassword", "Confirm Password"}, {"CreateRecoveryKey", "Create recovery key file"},
                {"FinishSetup", "Finish Setup"}, {"EnterMasterPassword", "Enter your master password"}, {"RecoverAccess", "Recover Access"}, {"ChooseKeyFile", "Choose Key File"},
                {"FileNotChosen", "File not chosen"}, {"ChangePassword", "Change Password"}, {"BackToLogin", "Back to Login"}, {"EntryDetails", "Entry Details"},
                {"Title", "Title:"}, {"LoginEmail", "Login/Email:"}, {"Password", "Password:"}, {"Notes", "Notes:"}, {"AddNew", "Add New"},
                {"Delete", "Delete"}, {"Logout", "Logout"}, {"Settings", "Settings"}, {"Language", "Language"}, {"VaultPath", "Vault Path"},
                {"Theme", "Theme"}, {"AccentColor", "Accent Color"}, {"Light", "Light"}, {"Dark", "Dark"}, {"Browse", "Browse..."}, {"Cancel", "Cancel"},
                {"PasswordCannotBeEmpty", "Password cannot be empty."}, {"PasswordsDoNotMatch", "Passwords do not match."}, {"Error", "Error"},
                {"SetupError", "Setup Error"}, {"Success", "Success"}, {"Info", "Information"}, {"RecoveryKeyCreationCancelled", "Recovery key file creation cancelled."},
                {"LoginError", "Login Error"}, {"VaultLoadError", "Vault Load Error"}, {"PleaseEnterPassword", "Please enter a password."},
                {"AccountNameCannotBeEmpty", "Account name cannot be empty."}, {"Saved", "Saved!"}, {"ConfirmDelete", "Confirm Delete"},
                {"ConfirmDeleteMessage", "Are you sure you want to delete the entry '{0}'?"}, {"VaultDecryptionError", "Failed to decrypt the vault. Incorrect password or corrupted file."},
                {"RecoveryPasswordResetWarning", "Password changed successfully! WARNING: The old password vault has been deleted."}, {"NewAccount", "New Account"},
                {"SaveKeyFileTitle", "Save Key File"}, {"SelectKeyFileTitle", "Select Key File"}, {"SettingsApplied", "Settings applied. Some changes may require a restart."},
                {"ChooseKeyFileError", "Please select a key file."}, {"PasswordsEmptyOrMismatch", "Passwords are empty or do not match."}
            }
        };

        public static void SetLanguage(string lang)
        {
            Thread.CurrentThread.CurrentUICulture = new CultureInfo(lang);
            _currentDict = AllStrings.ContainsKey(lang) ? AllStrings[lang] : AllStrings["en-US"];
        }
        public static string T(string key) => _currentDict.TryGetValue(key, out var value) ? value : key;
    }

    public static class ThemeManager
    {
        public static void Apply(Control parent, AppSettings settings)
        {
            bool isDark = settings.Theme == "Dark";
            Color backColor = isDark ? Color.FromArgb(45, 45, 48) : Color.WhiteSmoke;
            Color foreColor = isDark ? Color.White : Color.Black;
            Color controlBack = isDark ? Color.FromArgb(60, 60, 63) : Color.White;
            Color accent = ColorTranslator.FromHtml(settings.AccentColor);

            parent.BackColor = backColor;
            parent.ForeColor = foreColor;

            foreach (Control c in parent.Controls)
            {
                Apply(c, settings); // Recursive call
                if (c is Button btn) { btn.BackColor = accent; btn.ForeColor = Color.White; btn.FlatStyle = FlatStyle.Flat; btn.FlatAppearance.BorderSize = 0; }
                if (c is TextBox || c is ListBox || c is ComboBox) { c.BackColor = controlBack; c.ForeColor = foreColor; if (c is ListBox lb) lb.BorderStyle = BorderStyle.None; }
                if (c is GroupBox gb) { gb.ForeColor = foreColor; }
            }
        }
    }
    #endregion

    #region PART 2: CORE LOGIC (Vault, Auth)
    //================================================================================
    // PART 2: CORE LOGIC (VAULT, AUTH)
    // Класи для керування сховищем та процесом автентифікації.
    //================================================================================
    public class VaultManager
    {
        private readonly string _vaultFile; private List<PasswordEntry> _entries; private byte[] _encryptionKey; public VaultManager(byte[] encryptionKey, string vaultPath) { _encryptionKey = encryptionKey; _vaultFile = vaultPath; _entries = new List<PasswordEntry>(); LoadVault(); }
        private void LoadVault() { if (!File.Exists(_vaultFile)) { _entries = new List<PasswordEntry>(); return; } try { string encryptedJson = File.ReadAllText(_vaultFile); if (string.IsNullOrEmpty(encryptedJson)) { _entries = new List<PasswordEntry>(); return; } string json = CryptoService.Decrypt(encryptedJson, _encryptionKey); _entries = JsonSerializer.Deserialize<List<PasswordEntry>>(json) ?? new List<PasswordEntry>(); } catch (Exception) { throw new CryptographicException(LocalizationService.T("VaultDecryptionError")); } }
        public void SaveVault() { var options = new JsonSerializerOptions { WriteIndented = true }; string json = JsonSerializer.Serialize(_entries, options); string encryptedJson = CryptoService.Encrypt(json, _encryptionKey); File.WriteAllText(_vaultFile, encryptedJson); }
        public static void CreateNewVault(string password, byte[] salt, string vaultPath) { if (File.Exists(vaultPath)) return; var key = CryptoService.DeriveKey(password, salt); string encryptedJson = CryptoService.Encrypt(JsonSerializer.Serialize(new List<PasswordEntry>()), key); File.WriteAllText(vaultPath, encryptedJson); }
        public List<PasswordEntry> GetEntries() => _entries.OrderBy(e => e.AccountName).ToList(); public PasswordEntry GetEntry(Guid id) => _entries.FirstOrDefault(e => e.Id == id); public void AddEntry(PasswordEntry entry) { _entries.Add(entry); }
        public void UpdateEntry(PasswordEntry entry) { var existing = GetEntry(entry.Id); if (existing != null) { existing.AccountName = entry.AccountName; existing.Username = entry.Username; existing.Password = entry.Password; existing.Notes = entry.Notes; } }
        public void DeleteEntry(Guid id) { _entries.RemoveAll(e => e.Id == id); }
    }
    public class AuthManager
    {
        private const string ConfigFile = "config.json"; private const int SaltSize = 16, KeyFileSize = 1024, Iterations = 480000; private AuthConfig _configData; public AuthManager() { _configData = LoadConfig(); }
        private AuthConfig LoadConfig() { if (!File.Exists(ConfigFile)) return new AuthConfig(); try { string json = File.ReadAllText(ConfigFile); return JsonSerializer.Deserialize<AuthConfig>(json) ?? new AuthConfig(); } catch { return new AuthConfig(); } }
        private bool SaveConfig() { try { var options = new JsonSerializerOptions { WriteIndented = true }; string json = JsonSerializer.Serialize(_configData, options); File.WriteAllText(ConfigFile, json); return true; } catch { return false; } }
        private byte[] HashData(byte[] data, byte[] salt) { using (var kdf = new Rfc2898DeriveBytes(data, salt, Iterations, HashAlgorithmName.SHA256)) { return kdf.GetBytes(32); } }
        public bool DoesConfigExist() => !string.IsNullOrEmpty(_configData.PasswordHash); public (bool Success, string Message) Setup(string password, string vaultPath, string keyFilepath = null) { byte[] passwordSalt = RandomNumberGenerator.GetBytes(SaltSize); byte[] passwordHash = HashData(Encoding.UTF8.GetBytes(password), passwordSalt); _configData = new AuthConfig { PasswordSalt = Convert.ToBase64String(passwordSalt), PasswordHash = Convert.ToBase64String(passwordHash) }; if (!string.IsNullOrEmpty(keyFilepath)) { try { byte[] keyData = RandomNumberGenerator.GetBytes(KeyFileSize); File.WriteAllBytes(keyFilepath, keyData); byte[] recoverySalt = RandomNumberGenerator.GetBytes(SaltSize); byte[] recoveryHash = HashData(keyData, recoverySalt); _configData.RecoverySalt = Convert.ToBase64String(recoverySalt); _configData.RecoveryHash = Convert.ToBase64String(recoveryHash); } catch (Exception ex) { return (false, $"{LocalizationService.T("SetupError")}: {ex.Message}"); } } if (SaveConfig()) { VaultManager.CreateNewVault(password, passwordSalt, vaultPath); return (true, LocalizationService.T("Success")); } return (false, LocalizationService.T("SetupError")); }
        public (bool Success, string Message, byte[] Key) Login(string password) { try { byte[] passwordSalt = Convert.FromBase64String(_configData.PasswordSalt); byte[] storedHash = Convert.FromBase64String(_configData.PasswordHash); byte[] enteredPasswordHash = HashData(Encoding.UTF8.GetBytes(password), passwordSalt); if (CryptographicOperations.FixedTimeEquals(storedHash, enteredPasswordHash)) { byte[] encryptionKey = CryptoService.DeriveKey(password, passwordSalt); return (true, LocalizationService.T("Success"), encryptionKey); } return (false, LocalizationService.T("LoginError"), null); } catch { return (false, LocalizationService.T("SetupError"), null); } }
        public (bool Success, string Message) RecoverAccess(string keyFilepath, string newPassword, string vaultPath) { if (string.IsNullOrEmpty(_configData.RecoveryHash)) return (false, LocalizationService.T("SetupError")); try { byte[] keyData = File.ReadAllBytes(keyFilepath); byte[] recoverySalt = Convert.FromBase64String(_configData.RecoverySalt); byte[] storedRecoveryHash = Convert.FromBase64String(_configData.RecoveryHash); byte[] enteredKeyHash = HashData(keyData, recoverySalt); if (CryptographicOperations.FixedTimeEquals(storedRecoveryHash, enteredKeyHash)) { byte[] passwordSalt = Convert.FromBase64String(_configData.PasswordSalt); byte[] newPasswordHash = HashData(Encoding.UTF8.GetBytes(newPassword), passwordSalt); _configData.PasswordHash = Convert.ToBase64String(newPasswordHash); if (SaveConfig()) { if (File.Exists(vaultPath)) File.Delete(vaultPath); VaultManager.CreateNewVault(newPassword, passwordSalt, vaultPath); return (true, LocalizationService.T("RecoveryPasswordResetWarning")); } return (false, LocalizationService.T("Error")); } return (false, LocalizationService.T("LoginError")); } catch (Exception ex) { return (false, $"{LocalizationService.T("Recovery")}: {ex.Message}"); } }
        public void ReloadConfig() => _configData = LoadConfig();
    }
    #endregion

    #region PART 3: GUI (Forms)
    //================================================================================
    // PART 3: GUI (FORMS)
    // Вікна програми: налаштування та головне вікно.
    //================================================================================
    public class SettingsForm : Form
    {
        private AppSettings _settings;
        private TextBox _vaultPathBox;
        private ComboBox _languageBox, _themeBox;
        private Button _accentColorButton;
        private Label _langLabel, _vaultLabel, _themeLabel, _accentLabel;
        private Button _saveButton, _cancelButton, _browseButton;

        public SettingsForm(AppSettings currentSettings)
        {
            _settings = currentSettings;
            InitializeComponent();
            LoadSettingsToUI();
            UpdateUIStrings();
            ThemeManager.Apply(this, _settings);
        }

        private void InitializeComponent()
        {
            this.Size = new Size(450, 350);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterParent;

            _langLabel = new Label { Location = new Point(20, 20), AutoSize = true };
            _languageBox = new ComboBox { Location = new Point(20, 45), Width = 390, DropDownStyle = ComboBoxStyle.DropDownList };
            _languageBox.Items.AddRange(new[] { "українська (uk-UA)", "English (en-US)" });

            _vaultLabel = new Label { Location = new Point(20, 80), AutoSize = true };
            _vaultPathBox = new TextBox { Location = new Point(20, 105), Width = 300 };
            _browseButton = new Button { Location = new Point(330, 104), Width = 80 };
            _browseButton.Click += (s, e) => { using (var sfd = new SaveFileDialog { Filter = "Vault File|*.dat", FileName = "vault.dat" }) { if (sfd.ShowDialog() == DialogResult.OK) _vaultPathBox.Text = sfd.FileName; } };

            _themeLabel = new Label { Location = new Point(20, 140), AutoSize = true };
            _themeBox = new ComboBox { Location = new Point(20, 165), Width = 180, DropDownStyle = ComboBoxStyle.DropDownList };

            _accentLabel = new Label { Location = new Point(230, 140), AutoSize = true };
            _accentColorButton = new Button { Location = new Point(230, 165), Width = 180 };
            _accentColorButton.Click += (s, e) => { using (var cd = new ColorDialog()) { if (cd.ShowDialog() == DialogResult.OK) _accentColorButton.BackColor = cd.Color; } };

            _saveButton = new Button { Location = new Point(220, 250), Width = 90 };
            _cancelButton = new Button { Location = new Point(320, 250), Width = 90 };

            _saveButton.Click += SaveButton_Click;
            _cancelButton.Click += (s, e) => this.Close();

            this.Controls.AddRange(new Control[] { _langLabel, _languageBox, _vaultLabel, _vaultPathBox, _browseButton, _themeLabel, _themeBox, _accentLabel, _accentColorButton, _saveButton, _cancelButton });
        }

        private void LoadSettingsToUI()
        {
            _languageBox.SelectedIndex = _settings.Language == "uk-UA" ? 0 : 1;
            _vaultPathBox.Text = _settings.VaultPath;
            _themeBox.Items.Clear();
            _themeBox.Items.AddRange(new[] { LocalizationService.T("Dark"), LocalizationService.T("Light") });
            _themeBox.SelectedItem = _settings.Theme == "Dark" ? LocalizationService.T("Dark") : LocalizationService.T("Light");
            _accentColorButton.BackColor = ColorTranslator.FromHtml(_settings.AccentColor);
        }

        private void UpdateUIStrings()
        {
            this.Text = LocalizationService.T("Settings");
            _langLabel.Text = LocalizationService.T("Language");
            _vaultLabel.Text = LocalizationService.T("VaultPath");
            _browseButton.Text = LocalizationService.T("Browse");
            _themeLabel.Text = LocalizationService.T("Theme");
            _accentLabel.Text = LocalizationService.T("AccentColor");
            _saveButton.Text = LocalizationService.T("Save");
            _cancelButton.Text = LocalizationService.T("Cancel");
        }

        private void SaveButton_Click(object sender, EventArgs e)
        {
            _settings.Language = ((string)_languageBox.SelectedItem).Contains("uk-UA") ? "uk-UA" : "en-US";
            _settings.VaultPath = _vaultPathBox.Text;
            _settings.Theme = _themeBox.SelectedItem.ToString() == LocalizationService.T("Dark") ? "Dark" : "Light";
            _settings.AccentColor = ColorTranslator.ToHtml(_accentColorButton.BackColor);

            SettingsManager.Save(_settings);
            this.DialogResult = DialogResult.OK;
            this.Close();
        }
    }

    public class MainForm : Form
    {
        // Core services
        private readonly AuthManager _authManager;
        private VaultManager _vaultManager;
        private AppSettings _settings;
        private byte[] _currentKey;
        private PasswordEntry _selectedEntry;
        private string _recoveryKeyPath;

        // Panels
        private Panel _setupPanel, _loginPanel, _recoveryPanel, _managerPanel;

        // Shared Controls
        private TextBox _setupPassEntry, _setupPassConfirmEntry, _loginPasswordEntry, _recoveryNewPass, _recoveryNewPassConfirm;
        private ListBox _accountsListBox;
        private TextBox _accountNameBox, _usernameBox, _passwordBox, _notesBox;

        // Controls that need text updated
        private Label _setupTitle, _loginTitle, _recoveryTitle, _keyPathLabel;
        private Label _titleLabel, _loginEmailLabel, _passwordLabel, _notesLabel;
        private CheckBox _createKeyCheckbox;
        private Button _setupButton, _loginButton, _recoveryFromLoginButton, _selectKeyButton, _recoverButton, _backToLoginButton;
        private Button _addNewButton, _saveButton, _deleteButton, _showPassButton, _logoutButton;
        private GroupBox _detailsGroup;


        public MainForm()
        {
            _settings = SettingsManager.Load();
            LocalizationService.SetLanguage(_settings.Language);
            _authManager = new AuthManager();
            InitializeComponent();
            ApplyAllSettings();

            this.Resize += MainForm_Resize;

            if (_authManager.DoesConfigExist()) ShowPanel(_loginPanel); else ShowPanel(_setupPanel);
        }

        private void CenterAuthPanel(Panel panel)
        {
            if (panel == null || panel.Controls.Count == 0) return;
            Control container = panel.Controls[0]; // Assume the first control is the container
            container.Left = (panel.ClientSize.Width - container.Width) / 2;
            container.Top = (panel.ClientSize.Height - container.Height) / 2;
        }

        private void MainForm_Resize(object sender, EventArgs e)
        {
            if (_setupPanel.Visible) CenterAuthPanel(_setupPanel);
            if (_loginPanel.Visible) CenterAuthPanel(_loginPanel);
            if (_recoveryPanel.Visible) CenterAuthPanel(_recoveryPanel);
        }

        private void InitializeComponent()
        {
            this.MinimumSize = new Size(700, 500);
            this.Size = new Size(800, 600);
            this.StartPosition = FormStartPosition.CenterScreen;
            CreateSetupPanel();
            CreateLoginPanel();
            CreateRecoveryPanel();
            CreateManagerPanel();
        }

        private void ShowPanel(Panel panelToShow)
        {
            if (_setupPanel != null) _setupPanel.Visible = _loginPanel.Visible = _recoveryPanel.Visible = _managerPanel.Visible = false;
            if (panelToShow != null)
            {
                panelToShow.Visible = true;
                CenterAuthPanel(panelToShow);
            }
        }

        private void ApplyAllSettings()
        {
            LocalizationService.SetLanguage(_settings.Language);
            UpdateUIStrings();
            ThemeManager.Apply(this, _settings);
        }

        private void UpdateUIStrings()
        {
            this.Text = LocalizationService.T("PasswordManager");
            _setupTitle.Text = LocalizationService.T("InitialSetup");
            _createKeyCheckbox.Text = LocalizationService.T("CreateRecoveryKey");
            _setupButton.Text = LocalizationService.T("FinishSetup");
            _loginTitle.Text = LocalizationService.T("Login");
            _loginButton.Text = LocalizationService.T("Login");
            _recoveryFromLoginButton.Text = LocalizationService.T("RecoverAccess");
            _recoveryTitle.Text = LocalizationService.T("Recovery");
            _selectKeyButton.Text = LocalizationService.T("ChooseKeyFile");
            if (string.IsNullOrEmpty(_recoveryKeyPath)) _keyPathLabel.Text = LocalizationService.T("FileNotChosen");
            _recoverButton.Text = LocalizationService.T("ChangePassword");
            _backToLoginButton.Text = LocalizationService.T("BackToLogin");
            _detailsGroup.Text = LocalizationService.T("EntryDetails");
            _titleLabel.Text = LocalizationService.T("Title");
            _loginEmailLabel.Text = LocalizationService.T("LoginEmail");
            _passwordLabel.Text = LocalizationService.T("Password");
            _notesLabel.Text = LocalizationService.T("Notes");
            _addNewButton.Text = LocalizationService.T("AddNew");
            _saveButton.Text = LocalizationService.T("Save");
            _deleteButton.Text = LocalizationService.T("Delete");
            _logoutButton.Text = LocalizationService.T("Logout");

            // Recenter titles inside their containers
            if (_setupTitle.Parent != null) _setupTitle.Left = (_setupTitle.Parent.Width - _setupTitle.Width) / 2;
            if (_loginTitle.Parent != null) _loginTitle.Left = (_loginTitle.Parent.Width - _loginTitle.Width) / 2;
            if (_recoveryTitle.Parent != null) _recoveryTitle.Left = (_recoveryTitle.Parent.Width - _recoveryTitle.Width) / 2;

            CenterAuthPanel(_setupPanel);
            CenterAuthPanel(_loginPanel);
            CenterAuthPanel(_recoveryPanel);
        }

        private void CreateManagerPanel()
        {
            _managerPanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(10) };
            var settingsButton = new Button { Text = "⚙️", Font = new Font("Segoe UI Emoji", 12F), Size = new Size(40, 40), Location = new Point(this.ClientSize.Width - 55, 10), Anchor = AnchorStyles.Top | AnchorStyles.Right };
            settingsButton.Click += (s, e) => { using (var settingsForm = new SettingsForm(_settings)) { if (settingsForm.ShowDialog() == DialogResult.OK) { _settings = SettingsManager.Load(); ApplyAllSettings(); MessageBox.Show(LocalizationService.T("SettingsApplied"), LocalizationService.T("Info"), MessageBoxButtons.OK, MessageBoxIcon.Information); } } };
            _accountsListBox = new ListBox { Location = new Point(10, 10), Size = new Size(200, this.ClientSize.Height - 70), Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left };
            _accountsListBox.SelectedIndexChanged += AccountsListBox_SelectedIndexChanged;
            _detailsGroup = new GroupBox { Location = new Point(220, 10), Size = new Size(this.ClientSize.Width - 290, this.ClientSize.Height - 70), Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right };
            _accountNameBox = new TextBox { Location = new Point(20, 40), Width = _detailsGroup.Width - 40, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            _usernameBox = new TextBox { Location = new Point(20, 80), Width = _detailsGroup.Width - 40, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            _passwordBox = new TextBox { Location = new Point(20, 120), Width = _detailsGroup.Width - 80, UseSystemPasswordChar = true, Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right };
            _showPassButton = new Button { Text = "👁", Location = new Point(_detailsGroup.Width - 55, 119), Size = new Size(35, 25), Anchor = AnchorStyles.Top | AnchorStyles.Right };
            _showPassButton.MouseDown += (s, e) => _passwordBox.UseSystemPasswordChar = false;
            _showPassButton.MouseUp += (s, e) => _passwordBox.UseSystemPasswordChar = true;
            _notesBox = new TextBox { Location = new Point(20, 160), Size = new Size(_detailsGroup.Width - 40, _detailsGroup.Height - 240), Multiline = true, Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right };
            _titleLabel = new Label { Location = new Point(20, 20), AutoSize = true }; _loginEmailLabel = new Label { Location = new Point(20, 60), AutoSize = true }; _passwordLabel = new Label { Location = new Point(20, 100), AutoSize = true }; _notesLabel = new Label { Location = new Point(20, 140), AutoSize = true };
            _detailsGroup.Controls.AddRange(new Control[] { _titleLabel, _accountNameBox, _loginEmailLabel, _usernameBox, _passwordLabel, _passwordBox, _showPassButton, _notesLabel, _notesBox });
            _addNewButton = new Button { Location = new Point(10, this.ClientSize.Height - 50), Anchor = AnchorStyles.Bottom | AnchorStyles.Left, Size = new Size(100, 30) };
            _saveButton = new Button { Location = new Point(_detailsGroup.Left, _detailsGroup.Bottom + 10), Anchor = AnchorStyles.Bottom | AnchorStyles.Left, Size = new Size(100, 30) };
            _deleteButton = new Button { Location = new Point(_saveButton.Right + 10, _saveButton.Top), Anchor = AnchorStyles.Bottom | AnchorStyles.Left, Size = new Size(100, 30) };
            _logoutButton = new Button { Location = new Point(this.ClientSize.Width - 110, _saveButton.Top), Anchor = AnchorStyles.Bottom | AnchorStyles.Right, Size = new Size(100, 30) };
            _addNewButton.Click += AddNewButton_Click; _saveButton.Click += SaveButton_Click; _deleteButton.Click += DeleteButton_Click; _logoutButton.Click += LogoutButton_Click;
            _managerPanel.Controls.AddRange(new Control[] { settingsButton, _accountsListBox, _detailsGroup, _addNewButton, _saveButton, _deleteButton, _logoutButton }); this.Controls.Add(_managerPanel);
        }

        private void CreateSetupPanel()
        {
            _setupPanel = new Panel { Dock = DockStyle.Fill };
            var container = new Panel { Size = new Size(300, 330), Anchor = AnchorStyles.None };

            _setupTitle = new Label { Font = new Font("Segoe UI", 16F, FontStyle.Bold), AutoSize = true, Location = new Point(0, 0) };
            _setupPassEntry = new TextBox { Size = new Size(250, 30), Location = new Point(25, 70) };
            _setupPassConfirmEntry = new TextBox { Size = new Size(250, 30), Location = new Point(25, 120), UseSystemPasswordChar = true };
            _createKeyCheckbox = new CheckBox { Size = new Size(250, 30), Location = new Point(25, 170) };
            _setupButton = new Button { Size = new Size(250, 40), Location = new Point(25, 220) };
            _setupButton.Click += HandleSetup;

            container.Controls.AddRange(new Control[] { _setupTitle, _setupPassEntry, _setupPassConfirmEntry, _createKeyCheckbox, _setupButton });
            _setupPanel.Controls.Add(container);
            this.Controls.Add(_setupPanel);
        }

        private void CreateLoginPanel()
        {
            _loginPanel = new Panel { Dock = DockStyle.Fill };
            var container = new Panel { Size = new Size(300, 320), Anchor = AnchorStyles.None };

            _loginTitle = new Label { Font = new Font("Segoe UI", 16F, FontStyle.Bold), AutoSize = true, Location = new Point(0, 0) };
            _loginPasswordEntry = new TextBox { Size = new Size(250, 30), Location = new Point(25, 70), UseSystemPasswordChar = true };
            _loginButton = new Button { Size = new Size(250, 40), Location = new Point(25, 120) };
            _recoveryFromLoginButton = new Button { Size = new Size(250, 40), Location = new Point(25, 170) };
            _loginButton.Click += HandleLogin;
            _recoveryFromLoginButton.Click += (s, e) => ShowPanel(_recoveryPanel);

            container.Controls.AddRange(new Control[] { _loginTitle, _loginPasswordEntry, _loginButton, _recoveryFromLoginButton });
            _loginPanel.Controls.Add(container);
            this.Controls.Add(_loginPanel);
        }

        private void CreateRecoveryPanel()
        {
            _recoveryPanel = new Panel { Dock = DockStyle.Fill };
            var container = new Panel { Size = new Size(300, 380), Anchor = AnchorStyles.None };

            _recoveryTitle = new Label { Font = new Font("Segoe UI", 16F, FontStyle.Bold), AutoSize = true, Location = new Point(0, 0) };
            _selectKeyButton = new Button { Size = new Size(250, 40), Location = new Point(25, 50) };
            _keyPathLabel = new Label { Size = new Size(250, 20), Location = new Point(25, 100), TextAlign = ContentAlignment.MiddleCenter };
            _recoveryNewPass = new TextBox { Size = new Size(250, 30), Location = new Point(25, 140), UseSystemPasswordChar = true };
            _recoveryNewPassConfirm = new TextBox { Size = new Size(250, 30), Location = new Point(25, 190), UseSystemPasswordChar = true };
            _recoverButton = new Button { Size = new Size(250, 40), Location = new Point(25, 240) };
            _backToLoginButton = new Button { Size = new Size(250, 40), Location = new Point(25, 290) };
            _selectKeyButton.Click += SelectRecoveryKeyFile;
            _recoverButton.Click += HandleRecovery;
            _backToLoginButton.Click += (s, e) => ShowPanel(_loginPanel);

            container.Controls.AddRange(new Control[] { _recoveryTitle, _selectKeyButton, _keyPathLabel, _recoveryNewPass, _recoveryNewPassConfirm, _recoverButton, _backToLoginButton });
            _recoveryPanel.Controls.Add(container);
            this.Controls.Add(_recoveryPanel);
        }

        private void HandleLogin(object sender, EventArgs e) { var (success, message, key) = _authManager.Login(_loginPasswordEntry.Text); if (success) { _currentKey = key; try { _vaultManager = new VaultManager(_currentKey, _settings.VaultPath); PopulateAccountsList(); SetDetailsPanelEnabled(false); ClearDetailsPanel(); ShowPanel(_managerPanel); } catch (Exception ex) { MessageBox.Show(ex.Message, LocalizationService.T("VaultLoadError"), MessageBoxButtons.OK, MessageBoxIcon.Error); } } else { MessageBox.Show(message, LocalizationService.T("LoginError"), MessageBoxButtons.OK, MessageBoxIcon.Error); } _loginPasswordEntry.Clear(); }
        private void PopulateAccountsList() { _accountsListBox.Items.Clear(); var entries = _vaultManager.GetEntries(); foreach (var entry in entries) { _accountsListBox.Items.Add(entry); } _accountsListBox.DisplayMember = "AccountName"; }
        private void AccountsListBox_SelectedIndexChanged(object sender, EventArgs e) { if (_accountsListBox.SelectedItem is PasswordEntry entry) { _selectedEntry = entry; _accountNameBox.Text = entry.AccountName; _usernameBox.Text = entry.Username; _passwordBox.Text = entry.Password; _notesBox.Text = entry.Notes; SetDetailsPanelEnabled(true); _deleteButton.Enabled = true; } }
        private void AddNewButton_Click(object sender, EventArgs e) { _accountsListBox.ClearSelected(); _selectedEntry = null; _accountNameBox.Text = LocalizationService.T("NewAccount"); _usernameBox.Clear(); _passwordBox.Clear(); _notesBox.Clear(); SetDetailsPanelEnabled(true); _deleteButton.Enabled = false; _accountNameBox.Focus(); }
        private void SaveButton_Click(object sender, EventArgs e) { if (string.IsNullOrWhiteSpace(_accountNameBox.Text)) { MessageBox.Show(LocalizationService.T("AccountNameCannotBeEmpty"), LocalizationService.T("Error"), MessageBoxButtons.OK, MessageBoxIcon.Warning); return; } if (_selectedEntry == null) { var newEntry = new PasswordEntry { Id = Guid.NewGuid() }; _vaultManager.AddEntry(newEntry); _selectedEntry = newEntry; } _selectedEntry.AccountName = _accountNameBox.Text; _selectedEntry.Username = _usernameBox.Text; _selectedEntry.Password = _passwordBox.Text; _selectedEntry.Notes = _notesBox.Text; _vaultManager.SaveVault(); int selectedIndex = _accountsListBox.SelectedIndex; PopulateAccountsList(); if (selectedIndex >= 0 && selectedIndex < _accountsListBox.Items.Count) { _accountsListBox.SelectedIndex = selectedIndex; } else { _accountsListBox.SelectedItem = _selectedEntry; } MessageBox.Show(LocalizationService.T("Saved"), LocalizationService.T("Success"), MessageBoxButtons.OK, MessageBoxIcon.Information); }
        private void DeleteButton_Click(object sender, EventArgs e) { if (_selectedEntry == null) return; var result = MessageBox.Show(string.Format(LocalizationService.T("ConfirmDeleteMessage"), _selectedEntry.AccountName), LocalizationService.T("ConfirmDelete"), MessageBoxButtons.YesNo, MessageBoxIcon.Question); if (result == DialogResult.Yes) { _vaultManager.DeleteEntry(_selectedEntry.Id); _vaultManager.SaveVault(); PopulateAccountsList(); ClearDetailsPanel(); SetDetailsPanelEnabled(false); } }
        private void LogoutButton_Click(object sender, EventArgs e) { _currentKey = null; _vaultManager = null; _selectedEntry = null; _loginPasswordEntry.Clear(); _passwordBox.Clear(); GC.Collect(); ShowPanel(_loginPanel); }
        private void SetDetailsPanelEnabled(bool isEnabled) { _accountNameBox.Enabled = isEnabled; _usernameBox.Enabled = isEnabled; _passwordBox.Enabled = isEnabled; _showPassButton.Enabled = isEnabled; _notesBox.Enabled = isEnabled; _saveButton.Enabled = isEnabled; _deleteButton.Enabled = isEnabled; }
        private void ClearDetailsPanel() { _accountNameBox.Clear(); _usernameBox.Clear(); _passwordBox.Clear(); _notesBox.Clear(); _selectedEntry = null; }
        private void HandleSetup(object sender, EventArgs e) { var p1 = _setupPassEntry.Text; var p2 = _setupPassConfirmEntry.Text; if (string.IsNullOrWhiteSpace(p1)) { MessageBox.Show(LocalizationService.T("PasswordCannotBeEmpty"), LocalizationService.T("Error"), MessageBoxButtons.OK, MessageBoxIcon.Warning); return; } if (p1 != p2) { MessageBox.Show(LocalizationService.T("PasswordsDoNotMatch"), LocalizationService.T("Error"), MessageBoxButtons.OK, MessageBoxIcon.Warning); return; } string keyFilepath = null; if (_createKeyCheckbox.Checked) { using (var sfd = new SaveFileDialog { Filter = "Key Files (*.key)|*.key", Title = LocalizationService.T("SaveKeyFileTitle") }) { if (sfd.ShowDialog() == DialogResult.OK) keyFilepath = sfd.FileName; else return; } } var (success, message) = _authManager.Setup(p1, _settings.VaultPath, keyFilepath); MessageBox.Show(message, success ? LocalizationService.T("Success") : LocalizationService.T("SetupError"), MessageBoxButtons.OK, success ? MessageBoxIcon.Information : MessageBoxIcon.Error); if (success) ShowPanel(_loginPanel); }
        private void SelectRecoveryKeyFile(object sender, EventArgs e) { using (var ofd = new OpenFileDialog { Filter = "Key Files (*.key)|*.key", Title = LocalizationService.T("SelectKeyFileTitle") }) { if (ofd.ShowDialog() == DialogResult.OK) { _recoveryKeyPath = ofd.FileName; _keyPathLabel.Text = Path.GetFileName(_recoveryKeyPath); } } }
        private void HandleRecovery(object sender, EventArgs e) { if (string.IsNullOrEmpty(_recoveryKeyPath)) { MessageBox.Show(LocalizationService.T("ChooseKeyFileError"), LocalizationService.T("Error"), MessageBoxButtons.OK, MessageBoxIcon.Warning); return; } var p1 = _recoveryNewPass.Text; var p2 = _recoveryNewPassConfirm.Text; if (string.IsNullOrWhiteSpace(p1) || p1 != p2) { MessageBox.Show(LocalizationService.T("PasswordsEmptyOrMismatch"), LocalizationService.T("Error"), MessageBoxButtons.OK, MessageBoxIcon.Warning); return; } var (success, message) = _authManager.RecoverAccess(_recoveryKeyPath, p1, _settings.VaultPath); MessageBox.Show(message, success ? LocalizationService.T("Success") : LocalizationService.T("Error"), MessageBoxButtons.OK, success ? MessageBoxIcon.Information : MessageBoxIcon.Error); if (success) { _authManager.ReloadConfig(); ShowPanel(_loginPanel); } }
    }
    #endregion

    #region PART 4: APPLICATION LAUNCH
    //================================================================================
    // PART 4: APPLICATION LAUNCH
    // Точка входу в програму.
    //================================================================================
    static class Program { [STAThread] static void Main() { Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false); Application.Run(new MainForm()); } }
    #endregion
}

