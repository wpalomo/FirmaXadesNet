namespace TestFirmaXades
{
    partial class FrmPrincipal
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
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
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.btnFirmar = new System.Windows.Forms.Button();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.btnSeleccionarFichero = new System.Windows.Forms.Button();
            this.txtFichero = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.rbEnveloped = new System.Windows.Forms.RadioButton();
            this.rbExternallyDetached = new System.Windows.Forms.RadioButton();
            this.rbInternnallyDetached = new System.Windows.Forms.RadioButton();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.saveFileDialog1 = new System.Windows.Forms.SaveFileDialog();
            this.label2 = new System.Windows.Forms.Label();
            this.txtURLSellado = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.txtOCSP = new System.Windows.Forms.TextBox();
            this.btnXadesT = new System.Windows.Forms.Button();
            this.btnXadesXL = new System.Windows.Forms.Button();
            this.btnGuardarFirma = new System.Windows.Forms.Button();
            this.btnCargarFirma = new System.Windows.Forms.Button();
            this.groupBox1.SuspendLayout();
            this.SuspendLayout();
            // 
            // btnFirmar
            // 
            this.btnFirmar.Location = new System.Drawing.Point(12, 308);
            this.btnFirmar.Name = "btnFirmar";
            this.btnFirmar.Size = new System.Drawing.Size(75, 23);
            this.btnFirmar.TabIndex = 0;
            this.btnFirmar.Text = "Firmar";
            this.btnFirmar.UseVisualStyleBackColor = true;
            this.btnFirmar.Click += new System.EventHandler(this.btnFirmar_Click);
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.btnSeleccionarFichero);
            this.groupBox1.Controls.Add(this.txtFichero);
            this.groupBox1.Controls.Add(this.label1);
            this.groupBox1.Controls.Add(this.rbEnveloped);
            this.groupBox1.Controls.Add(this.rbExternallyDetached);
            this.groupBox1.Controls.Add(this.rbInternnallyDetached);
            this.groupBox1.Location = new System.Drawing.Point(12, 8);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(606, 176);
            this.groupBox1.TabIndex = 1;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Formato de firma";
            // 
            // btnSeleccionarFichero
            // 
            this.btnSeleccionarFichero.Location = new System.Drawing.Point(425, 128);
            this.btnSeleccionarFichero.Name = "btnSeleccionarFichero";
            this.btnSeleccionarFichero.Size = new System.Drawing.Size(28, 23);
            this.btnSeleccionarFichero.TabIndex = 5;
            this.btnSeleccionarFichero.Text = "...";
            this.btnSeleccionarFichero.UseVisualStyleBackColor = true;
            this.btnSeleccionarFichero.Click += new System.EventHandler(this.btnSeleccionarFichero_Click);
            // 
            // txtFichero
            // 
            this.txtFichero.Location = new System.Drawing.Point(13, 129);
            this.txtFichero.Name = "txtFichero";
            this.txtFichero.Size = new System.Drawing.Size(412, 20);
            this.txtFichero.TabIndex = 4;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(10, 112);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(78, 13);
            this.label1.TabIndex = 3;
            this.label1.Text = "Fichero original";
            // 
            // rbEnveloped
            // 
            this.rbEnveloped.AutoSize = true;
            this.rbEnveloped.Location = new System.Drawing.Point(13, 75);
            this.rbEnveloped.Name = "rbEnveloped";
            this.rbEnveloped.Size = new System.Drawing.Size(76, 17);
            this.rbEnveloped.TabIndex = 2;
            this.rbEnveloped.Text = "Enveloped";
            this.rbEnveloped.UseVisualStyleBackColor = true;
            // 
            // rbExternallyDetached
            // 
            this.rbExternallyDetached.AutoSize = true;
            this.rbExternallyDetached.Location = new System.Drawing.Point(13, 51);
            this.rbExternallyDetached.Name = "rbExternallyDetached";
            this.rbExternallyDetached.Size = new System.Drawing.Size(118, 17);
            this.rbExternallyDetached.TabIndex = 1;
            this.rbExternallyDetached.Text = "Externally detached";
            this.rbExternallyDetached.UseVisualStyleBackColor = true;
            // 
            // rbInternnallyDetached
            // 
            this.rbInternnallyDetached.AutoSize = true;
            this.rbInternnallyDetached.Checked = true;
            this.rbInternnallyDetached.Location = new System.Drawing.Point(13, 27);
            this.rbInternnallyDetached.Name = "rbInternnallyDetached";
            this.rbInternnallyDetached.Size = new System.Drawing.Size(115, 17);
            this.rbInternnallyDetached.TabIndex = 0;
            this.rbInternnallyDetached.TabStop = true;
            this.rbInternnallyDetached.Text = "Internally detached";
            this.rbInternnallyDetached.UseVisualStyleBackColor = true;
            // 
            // saveFileDialog1
            // 
            this.saveFileDialog1.Filter = "XML|*.xml";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(13, 195);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(154, 13);
            this.label2.TabIndex = 2;
            this.label2.Text = "URL servidor sellado de tiempo";
            // 
            // txtURLSellado
            // 
            this.txtURLSellado.Location = new System.Drawing.Point(16, 212);
            this.txtURLSellado.Name = "txtURLSellado";
            this.txtURLSellado.Size = new System.Drawing.Size(265, 20);
            this.txtURLSellado.TabIndex = 3;
            this.txtURLSellado.Text = "http://tss.accv.es:8318/tsa";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(299, 195);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(93, 13);
            this.label3.TabIndex = 4;
            this.label3.Text = "OCSP por defecto";
            // 
            // txtOCSP
            // 
            this.txtOCSP.Location = new System.Drawing.Point(302, 211);
            this.txtOCSP.Name = "txtOCSP";
            this.txtOCSP.Size = new System.Drawing.Size(314, 20);
            this.txtOCSP.TabIndex = 5;
            this.txtOCSP.Text = "http://ocsp.dnie.es";
            // 
            // btnXadesT
            // 
            this.btnXadesT.Location = new System.Drawing.Point(101, 308);
            this.btnXadesT.Name = "btnXadesT";
            this.btnXadesT.Size = new System.Drawing.Size(144, 23);
            this.btnXadesT.TabIndex = 6;
            this.btnXadesT.Text = "Ampliar a XADES-T";
            this.btnXadesT.UseVisualStyleBackColor = true;
            this.btnXadesT.Click += new System.EventHandler(this.btnXadesT_Click);
            // 
            // btnXadesXL
            // 
            this.btnXadesXL.Location = new System.Drawing.Point(259, 308);
            this.btnXadesXL.Name = "btnXadesXL";
            this.btnXadesXL.Size = new System.Drawing.Size(134, 23);
            this.btnXadesXL.TabIndex = 7;
            this.btnXadesXL.Text = "Ampliar a XADES-XL";
            this.btnXadesXL.UseVisualStyleBackColor = true;
            this.btnXadesXL.Click += new System.EventHandler(this.btnXadesXL_Click);
            // 
            // btnGuardarFirma
            // 
            this.btnGuardarFirma.Location = new System.Drawing.Point(516, 307);
            this.btnGuardarFirma.Name = "btnGuardarFirma";
            this.btnGuardarFirma.Size = new System.Drawing.Size(97, 23);
            this.btnGuardarFirma.TabIndex = 8;
            this.btnGuardarFirma.Text = "Guardar firma";
            this.btnGuardarFirma.UseVisualStyleBackColor = true;
            this.btnGuardarFirma.Click += new System.EventHandler(this.btnGuardarFirma_Click);
            // 
            // btnCargarFirma
            // 
            this.btnCargarFirma.Location = new System.Drawing.Point(516, 263);
            this.btnCargarFirma.Name = "btnCargarFirma";
            this.btnCargarFirma.Size = new System.Drawing.Size(97, 23);
            this.btnCargarFirma.TabIndex = 9;
            this.btnCargarFirma.Text = "Cargar firma";
            this.btnCargarFirma.UseVisualStyleBackColor = true;
            this.btnCargarFirma.Click += new System.EventHandler(this.btnCargarFirma_Click);
            // 
            // FrmPrincipal
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(630, 343);
            this.Controls.Add(this.btnCargarFirma);
            this.Controls.Add(this.btnGuardarFirma);
            this.Controls.Add(this.btnXadesXL);
            this.Controls.Add(this.btnXadesT);
            this.Controls.Add(this.txtOCSP);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.txtURLSellado);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.btnFirmar);
            this.Name = "FrmPrincipal";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Test firma Xades";
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button btnFirmar;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.RadioButton rbExternallyDetached;
        private System.Windows.Forms.RadioButton rbInternnallyDetached;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.RadioButton rbEnveloped;
        private System.Windows.Forms.Button btnSeleccionarFichero;
        private System.Windows.Forms.TextBox txtFichero;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
        private System.Windows.Forms.SaveFileDialog saveFileDialog1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox txtURLSellado;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox txtOCSP;
        private System.Windows.Forms.Button btnXadesT;
        private System.Windows.Forms.Button btnXadesXL;
        private System.Windows.Forms.Button btnGuardarFirma;
        private System.Windows.Forms.Button btnCargarFirma;
    }
}

