import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.util.Random;

public class Core extends JFrame {
    private JTextField nameField;
    private JPasswordField passwordField;
    private JTextField categoryField;
    private JTextField loginField;
    private JTextField urlField;
    private JTable passwordTable;
    private DefaultTableModel tableModel;

    public Core() {
        setTitle("Password Manager");
        setSize(1024, 768);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        initializeUI();
    }

    private void initializeUI() {
        JMenuBar menuBar = new JMenuBar();
        JMenu fileMenu = new JMenu("File");
        JMenuItem openFile = new JMenuItem("Open");
        JMenuItem saveFile = new JMenuItem("Save");
        JMenuItem exitItem = new JMenuItem("Exit");

        fileMenu.add(openFile);
        fileMenu.add(saveFile);
        fileMenu.addSeparator();
        fileMenu.add(exitItem);
        menuBar.add(fileMenu);
        setJMenuBar(menuBar);

        JPanel mainPanel = new JPanel(new BorderLayout());
        add(mainPanel, BorderLayout.CENTER);

        // Panel z tabelą haseł
        passwordTable = new JTable();
        initializeTable();
        JScrollPane tableScrollPane = new JScrollPane(passwordTable);
        mainPanel.add(tableScrollPane, BorderLayout.CENTER);

        
        JPanel detailPanel = new JPanel(new GridLayout(6, 2));
        detailPanel.add(new JLabel("Name:"));
        nameField = new JTextField();
        detailPanel.add(nameField);
        detailPanel.add(new JLabel("Password:"));
        passwordField = new JPasswordField();
        detailPanel.add(passwordField);
        detailPanel.add(new JLabel("Category:"));
        categoryField = new JTextField();
        detailPanel.add(categoryField);
        detailPanel.add(new JLabel("Login (opcjonalne):"));
        loginField = new JTextField();
        detailPanel.add(loginField);
        detailPanel.add(new JLabel("URL (opcjonalne):"));
        urlField = new JTextField();
        detailPanel.add(urlField);

        JButton generatePasswordButton = new JButton("Generate Password");
        generatePasswordButton.addActionListener(e -> passwordField.setText(generatePassword()));
        detailPanel.add(generatePasswordButton);

        JButton saveButton = new JButton("Save");
        saveButton.addActionListener(e -> savePassword());
        detailPanel.add(saveButton);

        mainPanel.add(detailPanel, BorderLayout.SOUTH);

        passwordTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    int selectedRow = passwordTable.getSelectedRow();
                    if (selectedRow != -1) {
                        
                        nameField.setText((String) passwordTable.getValueAt(selectedRow, 0));
                        categoryField.setText((String) passwordTable.getValueAt(selectedRow, 1));
                        loginField.setText((String) passwordTable.getValueAt(selectedRow, 2));
                        urlField.setText((String) passwordTable.getValueAt(selectedRow, 3));

                        
                        String encryptedPassword = (String) passwordTable.getValueAt(selectedRow, 4);
                        String key = JOptionPane.showInputDialog(Core.this, "Enter the master password to decrypt:");
                        try {
                            String decryptedPassword = EncryptionUtil.decrypt(encryptedPassword, key);
                            passwordField.setText(decryptedPassword);
                        } catch (Exception ex) {
                            ex.printStackTrace();
                            JOptionPane.showMessageDialog(Core.this, "Błąd podczas deszyfrowania hasła", "Błąd", JOptionPane.ERROR_MESSAGE);
                        }
                    }
                }
            }
        });

        openFile.addActionListener(e -> openFile());
        saveFile.addActionListener(e -> saveFile());
        exitItem.addActionListener(e -> System.exit(0));
    }

    private void initializeTable() {
        String[] columnNames = {"Nazwa", "Kategoria", "Login", "Strona WWW", "Zaszyfrowane Hasło"};
        Object[][] data = {}; 
        tableModel = new DefaultTableModel(data, columnNames) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; 
            }
        };
        passwordTable.setModel(tableModel);
    }

    private String generatePassword() {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder password = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < 12; i++) {
            password.append(characters.charAt(random.nextInt(characters.length())));
        }
        return password.toString();
    }

    private boolean validateInput() {
        if (nameField.getText().isEmpty() || passwordField.getPassword().length == 0 || categoryField.getText().isEmpty()) {
            JOptionPane.showMessageDialog(this, "Wszystkie wymagane pola muszą być wypełnione.", "Błąd walidacji", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        return true;
    }

    private void savePassword() {
        if (!validateInput()) {
            return;
        }

        String name = nameField.getText();
        String password = new String(passwordField.getPassword());
        String category = categoryField.getText();
        String login = loginField.getText();
        String url = urlField.getText();

       
        String key = JOptionPane.showInputDialog(this, "Enter the master password to encrypt:");
        try {
            String encryptedPassword = EncryptionUtil.encrypt(password, key);
            tableModel.addRow(new Object[]{name, category, login, url, encryptedPassword});
        } catch (Exception e) {
            e.printStackTrace();
        }

        clearFields();
    }

    private void clearFields() {
        nameField.setText("");
        passwordField.setText("");
        categoryField.setText("");
        loginField.setText("");
        urlField.setText("");
    }

    private void openFile() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
    
            try (BufferedReader reader = new BufferedReader(new FileReader(selectedFile))) {
                String key = JOptionPane.showInputDialog(this, "Enter the master password:");
                tableModel.setRowCount(0); 
                String line;
                while ((line = reader.readLine()) != null) {
                    String decryptedLine = EncryptionUtil.decrypt(line, key);
                    String[] data = decryptedLine.split(",");
                    tableModel.addRow(data);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void saveFile() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showSaveDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
          try (BufferedWriter writer = new BufferedWriter(new FileWriter(selectedFile))) {
                String key = JOptionPane.showInputDialog(this, "Enter the master password:");
                for (int row = 0; row < tableModel.getRowCount(); row++) {
                    StringBuilder rowString = new StringBuilder();
                    for (int col = 0; col < tableModel.getColumnCount(); col++) {
                        rowString.append(tableModel.getValueAt(row, col));
                        if (col < tableModel.getColumnCount() - 1) {
                            rowString.append(",");
                        }
                    }
                    String encryptedLine = EncryptionUtil.encrypt(rowString.toString(), key);
                    writer.write(encryptedLine);
                    writer.newLine();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    static class EncryptionUtil {
        public static String encrypt(String data, String key) {
            StringBuilder result = new StringBuilder();
            for (char character : data.toCharArray()) {
                result.append((char) (character + key.length()));
            }
            return result.toString();
        }

        public static String decrypt(String data, String key) {
            StringBuilder result = new StringBuilder();
            for (char character : data.toCharArray()) {
                result.append((char) (character - key.length()));
            }
            return result.toString();
        }
    }
}