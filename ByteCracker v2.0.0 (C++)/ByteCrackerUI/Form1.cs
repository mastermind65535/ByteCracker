using System;
using System.IO;
using System.Reflection;

namespace ByteCrackerUI
{
    public partial class Form1 : Form
    {
        public static string TARGET_PROJECT { get; set; }
        public static string _EXECUTEABLE_PATH = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        public static string _USER_PATH = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        public static string _SETTING_FILE = Path.Combine(_EXECUTEABLE_PATH, ".settings");
        public static string _PROJECT_DIR = "";
        public static string _INIT_SETTING_FILE = @"
project_dir={_USER_PATH};
";
        public Form1()
        {
            InitializeComponent();
        }

        private void UpdateProjectView()
        {
            _PROJECT_CONTROL.Text = $"Project - {TARGET_PROJECT}";
        }

        private void _PROJECTS_ItemActivate(object sender, EventArgs e)
        {
            TARGET_PROJECT = _PROJECTS.SelectedItems[0].Text;
            UpdateProjectView();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            if (!File.Exists(_SETTING_FILE)) { File.WriteAllText(_SETTING_FILE, Other._initSettings(_INIT_SETTING_FILE)); }
            string SETTINGS = File.ReadAllText(_SETTING_FILE);
            foreach (string setting in SETTINGS.Split(';')) {
                try
                {
                    string key = setting.Trim().Split('=')[0];
                    string value = setting.Trim().Split('=')[1].Split('\n')[0];
                    if (key == "project_dir")
                    {
                        _PROJECT_DIR = value;
                    }
                }
                catch(Exception ex)
                {
                    continue;
                }
            }

            if (!Directory.Exists(_PROJECT_DIR)) { Directory.CreateDirectory(_PROJECT_DIR); }

            _PROJECTS.Items.Clear();
            foreach (string project_name in Directory.GetDirectories(_PROJECT_DIR))
            {
                string ProjectName = project_name.Split('\\').Last();
                string CreationTime = Directory.GetCreationTime(project_name).ToString("yyyy-MM-dd-hh:mm:ss tt");
                ListViewItem ProjectItem = new ListViewItem();
                ProjectItem.Text = ProjectName;
                ProjectItem.ImageIndex = 1;
                ProjectItem.SubItems.Add(CreationTime);
                _PROJECTS.Items.Add(ProjectItem);
            }
        }
    }

    class Other
    {
        public static string _initSettings(string settingText)
        {
            settingText = settingText.Replace("{_USER_PATH}", Path.Combine(Form1._USER_PATH, "ByteCrackerProjects"));
            return settingText;
        }
    }
}
