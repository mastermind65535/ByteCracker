namespace ByteCrackerUI
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            ListViewItem listViewItem3 = new ListViewItem(new string[] { "Placeholder Project", "2024-12/10-09:47 PM", "0B" }, 1);
            ListViewItem listViewItem4 = new ListViewItem(new string[] { "Test Project", "2024-12/10-09:51 PM" }, 1);
            toolStrip1 = new ToolStrip();
            toolStripLabel1 = new ToolStripLabel();
            toolStripSeparator1 = new ToolStripSeparator();
            toolStripDropDownButton1 = new ToolStripDropDownButton();
            newToolStripMenuItem = new ToolStripMenuItem();
            loadToolStripMenuItem = new ToolStripMenuItem();
            toolStripDropDownButton2 = new ToolStripDropDownButton();
            toolStripMenuItem1 = new ToolStripMenuItem();
            _PROJECT_DIR_PATH = new ToolStripMenuItem();
            splitContainer1 = new SplitContainer();
            panel1 = new Panel();
            _PROJECT_IMAGE = new PictureBox();
            _PROJECT_CONTROL = new GroupBox();
            _PROJECT_OPEN = new Button();
            _PROJECT_DETAILS = new Button();
            _PROJECT_EXPORT = new Button();
            _PROJECT_REMOVE = new Button();
            panel2 = new Panel();
            _PROJECTS = new ListView();
            _PROJECT_NAME = new ColumnHeader();
            _PROJECT_CREATION_TIME = new ColumnHeader();
            _PROJECT_IMAGES = new ImageList(components);
            toolStrip1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)splitContainer1).BeginInit();
            splitContainer1.Panel1.SuspendLayout();
            splitContainer1.Panel2.SuspendLayout();
            splitContainer1.SuspendLayout();
            panel1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)_PROJECT_IMAGE).BeginInit();
            _PROJECT_CONTROL.SuspendLayout();
            panel2.SuspendLayout();
            SuspendLayout();
            // 
            // toolStrip1
            // 
            toolStrip1.Items.AddRange(new ToolStripItem[] { toolStripLabel1, toolStripSeparator1, toolStripDropDownButton1, toolStripDropDownButton2 });
            toolStrip1.Location = new Point(0, 0);
            toolStrip1.Name = "toolStrip1";
            toolStrip1.Size = new Size(1184, 31);
            toolStrip1.TabIndex = 0;
            toolStrip1.Text = "toolStrip1";
            // 
            // toolStripLabel1
            // 
            toolStripLabel1.DisplayStyle = ToolStripItemDisplayStyle.Text;
            toolStripLabel1.Font = new Font("Agency FB", 18F, FontStyle.Regular, GraphicsUnit.Point, 0);
            toolStripLabel1.Name = "toolStripLabel1";
            toolStripLabel1.Size = new Size(105, 28);
            toolStripLabel1.Text = "ByteCracker";
            // 
            // toolStripSeparator1
            // 
            toolStripSeparator1.Name = "toolStripSeparator1";
            toolStripSeparator1.Size = new Size(6, 31);
            // 
            // toolStripDropDownButton1
            // 
            toolStripDropDownButton1.DisplayStyle = ToolStripItemDisplayStyle.Text;
            toolStripDropDownButton1.DropDownItems.AddRange(new ToolStripItem[] { newToolStripMenuItem, loadToolStripMenuItem });
            toolStripDropDownButton1.Image = (Image)resources.GetObject("toolStripDropDownButton1.Image");
            toolStripDropDownButton1.ImageTransparentColor = Color.Magenta;
            toolStripDropDownButton1.Name = "toolStripDropDownButton1";
            toolStripDropDownButton1.Size = new Size(57, 28);
            toolStripDropDownButton1.Text = "Project";
            // 
            // newToolStripMenuItem
            // 
            newToolStripMenuItem.Name = "newToolStripMenuItem";
            newToolStripMenuItem.Size = new Size(106, 22);
            newToolStripMenuItem.Text = "New..";
            // 
            // loadToolStripMenuItem
            // 
            loadToolStripMenuItem.Name = "loadToolStripMenuItem";
            loadToolStripMenuItem.Size = new Size(106, 22);
            loadToolStripMenuItem.Text = "Load..";
            // 
            // toolStripDropDownButton2
            // 
            toolStripDropDownButton2.DisplayStyle = ToolStripItemDisplayStyle.Text;
            toolStripDropDownButton2.DropDownItems.AddRange(new ToolStripItem[] { toolStripMenuItem1 });
            toolStripDropDownButton2.Image = (Image)resources.GetObject("toolStripDropDownButton2.Image");
            toolStripDropDownButton2.ImageTransparentColor = Color.Magenta;
            toolStripDropDownButton2.Name = "toolStripDropDownButton2";
            toolStripDropDownButton2.Size = new Size(62, 28);
            toolStripDropDownButton2.Text = "Settings";
            // 
            // toolStripMenuItem1
            // 
            toolStripMenuItem1.DropDownItems.AddRange(new ToolStripItem[] { _PROJECT_DIR_PATH });
            toolStripMenuItem1.Name = "toolStripMenuItem1";
            toolStripMenuItem1.Size = new Size(162, 22);
            toolStripMenuItem1.Text = "Project Directory";
            // 
            // _PROJECT_DIR_PATH
            // 
            _PROJECT_DIR_PATH.Name = "_PROJECT_DIR_PATH";
            _PROJECT_DIR_PATH.Size = new Size(177, 22);
            _PROJECT_DIR_PATH.Text = "PROJECT_DIR_PATH";
            // 
            // splitContainer1
            // 
            splitContainer1.Dock = DockStyle.Fill;
            splitContainer1.Location = new Point(0, 31);
            splitContainer1.Name = "splitContainer1";
            // 
            // splitContainer1.Panel1
            // 
            splitContainer1.Panel1.Controls.Add(panel1);
            // 
            // splitContainer1.Panel2
            // 
            splitContainer1.Panel2.Controls.Add(panel2);
            splitContainer1.Size = new Size(1184, 530);
            splitContainer1.SplitterDistance = 310;
            splitContainer1.TabIndex = 1;
            // 
            // panel1
            // 
            panel1.Controls.Add(_PROJECT_IMAGE);
            panel1.Controls.Add(_PROJECT_CONTROL);
            panel1.Dock = DockStyle.Fill;
            panel1.Location = new Point(0, 0);
            panel1.Name = "panel1";
            panel1.Size = new Size(310, 530);
            panel1.TabIndex = 0;
            // 
            // _PROJECT_IMAGE
            // 
            _PROJECT_IMAGE.Dock = DockStyle.Top;
            _PROJECT_IMAGE.Image = Properties.Resources.logo_no_background;
            _PROJECT_IMAGE.Location = new Point(0, 0);
            _PROJECT_IMAGE.Name = "_PROJECT_IMAGE";
            _PROJECT_IMAGE.Size = new Size(310, 210);
            _PROJECT_IMAGE.SizeMode = PictureBoxSizeMode.Zoom;
            _PROJECT_IMAGE.TabIndex = 1;
            _PROJECT_IMAGE.TabStop = false;
            // 
            // _PROJECT_CONTROL
            // 
            _PROJECT_CONTROL.Controls.Add(_PROJECT_OPEN);
            _PROJECT_CONTROL.Controls.Add(_PROJECT_DETAILS);
            _PROJECT_CONTROL.Controls.Add(_PROJECT_EXPORT);
            _PROJECT_CONTROL.Controls.Add(_PROJECT_REMOVE);
            _PROJECT_CONTROL.Dock = DockStyle.Bottom;
            _PROJECT_CONTROL.Location = new Point(0, 415);
            _PROJECT_CONTROL.Name = "_PROJECT_CONTROL";
            _PROJECT_CONTROL.Size = new Size(310, 115);
            _PROJECT_CONTROL.TabIndex = 0;
            _PROJECT_CONTROL.TabStop = false;
            _PROJECT_CONTROL.Text = "Project Control";
            // 
            // _PROJECT_OPEN
            // 
            _PROJECT_OPEN.Dock = DockStyle.Bottom;
            _PROJECT_OPEN.ForeColor = Color.Green;
            _PROJECT_OPEN.Location = new Point(3, 20);
            _PROJECT_OPEN.Name = "_PROJECT_OPEN";
            _PROJECT_OPEN.Size = new Size(304, 23);
            _PROJECT_OPEN.TabIndex = 0;
            _PROJECT_OPEN.Text = "Open";
            _PROJECT_OPEN.TextAlign = ContentAlignment.MiddleLeft;
            _PROJECT_OPEN.UseVisualStyleBackColor = true;
            // 
            // _PROJECT_DETAILS
            // 
            _PROJECT_DETAILS.Dock = DockStyle.Bottom;
            _PROJECT_DETAILS.ForeColor = Color.Navy;
            _PROJECT_DETAILS.Location = new Point(3, 43);
            _PROJECT_DETAILS.Name = "_PROJECT_DETAILS";
            _PROJECT_DETAILS.Size = new Size(304, 23);
            _PROJECT_DETAILS.TabIndex = 3;
            _PROJECT_DETAILS.Text = "Details";
            _PROJECT_DETAILS.TextAlign = ContentAlignment.MiddleLeft;
            _PROJECT_DETAILS.UseVisualStyleBackColor = true;
            // 
            // _PROJECT_EXPORT
            // 
            _PROJECT_EXPORT.Dock = DockStyle.Bottom;
            _PROJECT_EXPORT.ForeColor = Color.Black;
            _PROJECT_EXPORT.Location = new Point(3, 66);
            _PROJECT_EXPORT.Name = "_PROJECT_EXPORT";
            _PROJECT_EXPORT.Size = new Size(304, 23);
            _PROJECT_EXPORT.TabIndex = 2;
            _PROJECT_EXPORT.Text = "Export";
            _PROJECT_EXPORT.TextAlign = ContentAlignment.MiddleLeft;
            _PROJECT_EXPORT.UseVisualStyleBackColor = true;
            // 
            // _PROJECT_REMOVE
            // 
            _PROJECT_REMOVE.Dock = DockStyle.Bottom;
            _PROJECT_REMOVE.ForeColor = Color.Red;
            _PROJECT_REMOVE.Location = new Point(3, 89);
            _PROJECT_REMOVE.Name = "_PROJECT_REMOVE";
            _PROJECT_REMOVE.Size = new Size(304, 23);
            _PROJECT_REMOVE.TabIndex = 1;
            _PROJECT_REMOVE.Text = "Remove";
            _PROJECT_REMOVE.TextAlign = ContentAlignment.MiddleLeft;
            _PROJECT_REMOVE.UseVisualStyleBackColor = true;
            // 
            // panel2
            // 
            panel2.Controls.Add(_PROJECTS);
            panel2.Dock = DockStyle.Fill;
            panel2.Location = new Point(0, 0);
            panel2.Name = "panel2";
            panel2.Size = new Size(870, 530);
            panel2.TabIndex = 0;
            // 
            // _PROJECTS
            // 
            _PROJECTS.Columns.AddRange(new ColumnHeader[] { _PROJECT_NAME, _PROJECT_CREATION_TIME });
            _PROJECTS.Dock = DockStyle.Fill;
            _PROJECTS.Items.AddRange(new ListViewItem[] { listViewItem3, listViewItem4 });
            _PROJECTS.LargeImageList = _PROJECT_IMAGES;
            _PROJECTS.Location = new Point(0, 0);
            _PROJECTS.Name = "_PROJECTS";
            _PROJECTS.Size = new Size(870, 530);
            _PROJECTS.TabIndex = 0;
            _PROJECTS.UseCompatibleStateImageBehavior = false;
            _PROJECTS.View = View.Tile;
            _PROJECTS.ItemActivate += _PROJECTS_ItemActivate;
            // 
            // _PROJECT_IMAGES
            // 
            _PROJECT_IMAGES.ColorDepth = ColorDepth.Depth32Bit;
            _PROJECT_IMAGES.ImageStream = (ImageListStreamer)resources.GetObject("_PROJECT_IMAGES.ImageStream");
            _PROJECT_IMAGES.TransparentColor = Color.Transparent;
            _PROJECT_IMAGES.Images.SetKeyName(0, "project.png");
            _PROJECT_IMAGES.Images.SetKeyName(1, "folder.png");
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(1184, 561);
            Controls.Add(splitContainer1);
            Controls.Add(toolStrip1);
            Icon = (Icon)resources.GetObject("$this.Icon");
            Name = "Form1";
            Text = "ByteCracker v1.0.0";
            Load += Form1_Load;
            toolStrip1.ResumeLayout(false);
            toolStrip1.PerformLayout();
            splitContainer1.Panel1.ResumeLayout(false);
            splitContainer1.Panel2.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)splitContainer1).EndInit();
            splitContainer1.ResumeLayout(false);
            panel1.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)_PROJECT_IMAGE).EndInit();
            _PROJECT_CONTROL.ResumeLayout(false);
            panel2.ResumeLayout(false);
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private ToolStrip toolStrip1;
        private ToolStripLabel toolStripLabel1;
        private ToolStripSeparator toolStripSeparator1;
        private ToolStripDropDownButton toolStripDropDownButton1;
        private ToolStripMenuItem newToolStripMenuItem;
        private ToolStripMenuItem loadToolStripMenuItem;
        private SplitContainer splitContainer1;
        private Panel panel1;
        private Panel panel2;
        private ListView _PROJECTS;
        private ColumnHeader _PROJECT_NAME;
        private ColumnHeader _PROJECT_CREATION_TIME;
        private ImageList _PROJECT_IMAGES;
        private GroupBox _PROJECT_CONTROL;
        private Button _PROJECT_DETAILS;
        private Button _PROJECT_EXPORT;
        private Button _PROJECT_REMOVE;
        private Button _PROJECT_OPEN;
        private PictureBox _PROJECT_IMAGE;
        private ToolStripDropDownButton toolStripDropDownButton2;
        private ToolStripMenuItem toolStripMenuItem1;
        private ToolStripMenuItem _PROJECT_DIR_PATH;
    }
}
