package burp.extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

public class TokenScanner implements BurpExtension {

    private MontoyaApi api;
    private DefaultTableModel tableModel;
    private JTable resultTable;
    private JLabel statusLabel;
    private JLabel alertLabel;
    private JSplitPane splitPane;
    private HttpRequestEditor requestEditor;
    private HttpResponseEditor responseEditor;
    private final List<TokenRecord> records = new CopyOnWriteArrayList<>();
    private final AtomicInteger idCounter = new AtomicInteger(0);
    private int blinkCount = 0;
    private Timer blinkTimer;
    private int currentClickIndex = 0; // 当前点击的索引，用于循环切换关键字
    private int lastClickedRow = -1; // 上次点击的行

    // 设置相关
    private JTextField keywordsField;
    private JRadioButton monitorBothRadio;
    private JRadioButton monitorRequestOnlyRadio;
    private JRadioButton monitorResponseOnlyRadio;
    private String keywords = "token";
    private int monitorMode = 0; // 0=both, 1=request only, 2=response only

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        api.extension().setName("Token Scanner");

        // 注册请求处理器
        api.proxy().registerRequestHandler(new ProxyRequestHandler() {
            @Override
            public ProxyRequestReceivedAction handleRequestReceived(burp.api.montoya.proxy.http.InterceptedRequest request) {
                try {
                    if (monitorMode == 2) return ProxyRequestReceivedAction.continueWith(request); // 只监控响应

                    String requestBody = request.bodyToString();
                    String fullRequest = request.toString();
                    String content = requestBody != null ? requestBody : fullRequest;

                    if (content != null) {
                        String matched = getMatchedKeywords(content);
                        if (matched != null) {
                            addRecord("REQUEST", request.httpService(), request.path(), request.method(),
                                    request.toString(), null, matched);
                        }
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[TokenScanner] Request error: " + ex.getMessage());
                }
                return ProxyRequestReceivedAction.continueWith(request);
            }

            @Override
            public ProxyRequestToBeSentAction handleRequestToBeSent(burp.api.montoya.proxy.http.InterceptedRequest request) {
                return ProxyRequestToBeSentAction.continueWith(request);
            }
        });

        // 注册响应处理器
        api.proxy().registerResponseHandler(new ProxyResponseHandler() {
            @Override
            public ProxyResponseReceivedAction handleResponseReceived(burp.api.montoya.proxy.http.InterceptedResponse response) {
                try {
                    if (monitorMode == 1) return ProxyResponseReceivedAction.continueWith(response); // 只监控请求

                    String responseBody = response.bodyToString();
                    String fullResponse = response.toString();
                    String content = responseBody != null ? responseBody : fullResponse;

                    if (content != null) {
                        String matched = getMatchedKeywords(content);
                        if (matched != null) {
                            HttpRequest initiatingRequest = response.initiatingRequest();
                            addRecord("RESPONSE", initiatingRequest.httpService(),
                                    initiatingRequest.path(),
                                    initiatingRequest.method(),
                                    initiatingRequest.toString(),
                                    response.toString(), matched);
                        }
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[TokenScanner] Response error: " + ex.getMessage());
                }
                return ProxyResponseReceivedAction.continueWith(response);
            }

            @Override
            public ProxyResponseToBeSentAction handleResponseToBeSent(burp.api.montoya.proxy.http.InterceptedResponse response) {
                return ProxyResponseToBeSentAction.continueWith(response);
            }
        });

        // 创建GUI
        createUI();

        api.logging().logToOutput("[TokenScanner] Extension loaded successfully!");

        // 延迟1秒后开始闪烁
        Timer startTimer = new Timer(1000, e -> startTabBlink());
        startTimer.setRepeats(false);
        startTimer.start();
    }

    /**
     * 获取所有匹配到的关键字
     */
    private String getMatchedKeywords(String content) {
        if (content == null || content.isEmpty()) {
            return null;
        }
        String lowerContent = content.toLowerCase();
        String[] keywordList = keywords.toLowerCase().split(",");
        List<String> matched = new java.util.ArrayList<>();
        for (String keyword : keywordList) {
            String trimmed = keyword.trim();
            if (!trimmed.isEmpty() && lowerContent.contains(trimmed)) {
                matched.add(trimmed);
            }
        }
        return matched.isEmpty() ? null : String.join(", ", matched);
    }

    /**
     * 添加记录
     */
    private void addRecord(String source, burp.api.montoya.http.HttpService httpService, String path,
                           String method, String rawRequest, String rawResponse, String matchedKeyword) {
        int id = idCounter.incrementAndGet();
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        String host = httpService.host();
        int port = httpService.port();

        // 构建完整URL
        String url = "https://" + host + (port != 443 ? ":" + port : "") + path;

        // 获取响应信息
        int statusCode = 0;
        int length = 0;
        String mimeType = "";
        String ip = "";

        if (rawResponse != null && !rawResponse.isEmpty()) {
            try {
                HttpResponse response = HttpResponse.httpResponse(rawResponse);
                statusCode = response.statusCode();
                length = response.bodyToString() != null ? response.bodyToString().length() : 0;
                mimeType = response.mimeType() != null ? response.mimeType().toString() : "";
            } catch (Exception e) {
                // 忽略解析错误
            }
        }

        TokenRecord record = new TokenRecord(id, source, host, method, url, statusCode, length, mimeType, ip, timestamp,
                httpService, rawRequest, rawResponse, matchedKeyword);
        records.add(record);

        // 在EDT中更新UI
        SwingUtilities.invokeLater(() -> {
            tableModel.addRow(new Object[]{
                    record.id,
                    record.host,
                    record.method,
                    record.url,
                    record.statusCode,
                    record.length,
                    record.mimeType,
                    record.ip,
                    record.timestamp,
                    record.source,
                    record.matchedKeyword
            });

            // 滚动到最新行
            resultTable.scrollRectToVisible(resultTable.getCellRect(tableModel.getRowCount() - 1, 0, true));

            // 更新状态栏
            statusLabel.setText("Found: " + records.size() + " tokens");

            // 显示警告并闪烁Tab
            alertLabel.setVisible(true);
            alertLabel.setText("  NEW!  ");
            startTabBlink();
        });

        api.logging().logToOutput("[TokenScanner] Token found - " + method + " " + url);
    }

    /**
     * 通过反射高亮Tab标题
     */
    private void highlightTab(String tabTitle, Color color) {
        try {
            Window[] windows = Window.getWindows();
            for (Window window : windows) {
                findAndHighlightTab(window, tabTitle, color, 0);
            }
        } catch (Exception e) {
            api.logging().logToError("[TokenScanner] Tab highlight error: " + e.getMessage());
        }
    }

    private void findAndHighlightTab(Component component, String tabTitle, Color color, int depth) {
        if (component == null || depth > 20) return;

        if (component instanceof JTabbedPane) {
            JTabbedPane tabbedPane = (JTabbedPane) component;
            for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                if (tabTitle.equals(tabbedPane.getTitleAt(i))) {
                    tabbedPane.setBackgroundAt(i, color);
                    return;
                }
            }
        }

        if (component instanceof Container) {
            for (Component child : ((Container) component).getComponents()) {
                findAndHighlightTab(child, tabTitle, color, depth + 1);
            }
        }
    }

    private void resetTabColor(String tabTitle) {
        try {
            Window[] windows = Window.getWindows();
            for (Window window : windows) {
                resetComponentColor(window, tabTitle);
            }
        } catch (Exception e) {
            api.logging().logToError("[TokenScanner] Tab reset error: " + e.getMessage());
        }
    }

    private void resetComponentColor(Component component, String tabTitle) {
        if (component == null) return;

        if (component instanceof JTabbedPane) {
            JTabbedPane tabbedPane = (JTabbedPane) component;
            for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                if (tabTitle.equals(tabbedPane.getTitleAt(i))) {
                    tabbedPane.setBackgroundAt(i, null);
                    tabbedPane.setForegroundAt(i, null);
                    return;
                }
            }
        }

        if (component instanceof Container) {
            for (Component child : ((Container) component).getComponents()) {
                resetComponentColor(child, tabTitle);
            }
        }
    }

    private void startTabBlink() {
        if (blinkTimer != null && blinkTimer.isRunning()) {
            blinkTimer.stop();
        }

        blinkCount = 0;
        blinkTimer = new Timer(400, e -> {
            blinkCount++;
            if (blinkCount % 2 == 0) {
                highlightTab("Token Scanner", Color.YELLOW);
            } else {
                resetTabColor("Token Scanner");
            }

            if (blinkCount >= 10) {
                blinkTimer.stop();
                resetTabColor("Token Scanner");
            }
        });
        blinkTimer.setInitialDelay(0);
        blinkTimer.start();
    }

    /**
     * 创建GUI界面
     */
    private void createUI() {
        // 创建主Tab面板
        JTabbedPane mainTabbedPane = new JTabbedPane();
        mainTabbedPane.addTab("History", createHistoryPanel());
        mainTabbedPane.addTab("Settings", createSettingsPanel());

        // 注册Tab
        api.userInterface().registerSuiteTab("Token Scanner", mainTabbedPane);
    }

    /**
     * 创建历史记录面板
     */
    private JPanel createHistoryPanel() {
        JPanel mainPanel = new JPanel(new BorderLayout());

        // 创建表格
        String[] columnNames = {"#", "Host", "Method", "URL", "Status", "Length", "MIME", "IP", "Time", "Source", "Matched"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        resultTable = new JTable(tableModel);
        resultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultTable.setAutoCreateRowSorter(true);

        // 设置列居中对齐（URL列居左）
        resultTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                           boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (column == 3) {
                    setHorizontalAlignment(SwingConstants.LEFT);
                } else {
                    setHorizontalAlignment(SwingConstants.CENTER);
                }
                return c;
            }
        });

        // 设置列宽
        resultTable.getColumnModel().getColumn(0).setPreferredWidth(40);   // #
        resultTable.getColumnModel().getColumn(1).setPreferredWidth(150);  // Host
        resultTable.getColumnModel().getColumn(2).setPreferredWidth(50);   // Method
        resultTable.getColumnModel().getColumn(3).setPreferredWidth(250);  // URL
        resultTable.getColumnModel().getColumn(4).setPreferredWidth(50);   // Status
        resultTable.getColumnModel().getColumn(5).setPreferredWidth(60);   // Length
        resultTable.getColumnModel().getColumn(6).setPreferredWidth(60);   // MIME
        resultTable.getColumnModel().getColumn(7).setPreferredWidth(100);  // IP
        resultTable.getColumnModel().getColumn(8).setPreferredWidth(70);   // Time
        resultTable.getColumnModel().getColumn(9).setPreferredWidth(70);   // Source
        resultTable.getColumnModel().getColumn(10).setPreferredWidth(80);  // Matched

        // 添加右键菜单
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyUrl = new JMenuItem("Copy URL");
        copyUrl.addActionListener(e -> {
            int row = resultTable.getSelectedRow();
            if (row >= 0) {
                int modelRow = resultTable.convertRowIndexToModel(row);
                String url = (String) tableModel.getValueAt(modelRow, 3);
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new java.awt.datatransfer.StringSelection(url), null);
            }
        });
        JMenuItem clearItem = new JMenuItem("Clear All");
        clearItem.addActionListener(e -> {
            tableModel.setRowCount(0);
            records.clear();
            idCounter.set(0);
            statusLabel.setText("Found: 0 tokens");
            alertLabel.setVisible(false);
            resetTabColor("Token Scanner");
            clearEditors();
        });
        popupMenu.add(copyUrl);
        popupMenu.addSeparator();
        popupMenu.add(clearItem);
        resultTable.setComponentPopupMenu(popupMenu);

        // 添加鼠标点击事件 - 显示请求/响应（支持重复点击切换关键字）
        resultTable.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                int row = resultTable.rowAtPoint(e.getPoint());
                if (row >= 0) {
                    int modelRow = resultTable.convertRowIndexToModel(row);
                    showRequestResponse(modelRow);
                }
            }
        });

        // 表格滚动面板
        JScrollPane tableScrollPane = new JScrollPane(resultTable);
        tableScrollPane.setBorder(BorderFactory.createEmptyBorder());

        // 创建请求/响应编辑器
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();

        // 创建下方的分割面板（请求 | 响应）- 各占一半
        JSplitPane bottomSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestEditor.uiComponent(), responseEditor.uiComponent());
        bottomSplitPane.setResizeWeight(0.5);
        bottomSplitPane.setDividerLocation(0.5);
        bottomSplitPane.setDividerSize(8);

        // 创建主分割面板（上方表格 | 下方编辑器）
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                tableScrollPane, bottomSplitPane);
        splitPane.setResizeWeight(0.4);
        splitPane.setDividerLocation(200);

        mainPanel.add(splitPane, BorderLayout.CENTER);

        // 底部状态栏
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        alertLabel = new JLabel("");
        alertLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        alertLabel.setForeground(Color.RED);
        alertLabel.setVisible(false);
        bottomPanel.add(alertLabel);

        statusLabel = new JLabel("Found: 0 tokens");
        statusLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        bottomPanel.add(statusLabel);

        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> {
            tableModel.setRowCount(0);
            records.clear();
            idCounter.set(0);
            statusLabel.setText("Found: 0 tokens");
            alertLabel.setVisible(false);
            resetTabColor("Token Scanner");
            clearEditors();
        });
        bottomPanel.add(clearBtn);

        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        return mainPanel;
    }

    /**
     * 创建设置面板
     */
    private JPanel createSettingsPanel() {
        JPanel settingsPanel = new JPanel(new BorderLayout());
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        // 关键字设置
        JPanel keywordsPanel = new JPanel(new BorderLayout(10, 0));
        keywordsPanel.setBorder(BorderFactory.createTitledBorder("Monitor Keywords"));
        JLabel keywordsLabel = new JLabel("Keywords (comma separated):");
        keywordsField = new JTextField("token", 30);
        keywordsPanel.add(keywordsLabel, BorderLayout.WEST);
        keywordsPanel.add(keywordsField, BorderLayout.CENTER);

        // 监控范围设置
        JPanel monitorPanel = new JPanel(new BorderLayout());
        monitorPanel.setBorder(BorderFactory.createTitledBorder("Monitor Scope"));
        monitorBothRadio = new JRadioButton("Monitor Both Request & Response", true);
        monitorRequestOnlyRadio = new JRadioButton("Monitor Request Only");
        monitorResponseOnlyRadio = new JRadioButton("Monitor Response Only");

        ButtonGroup group = new ButtonGroup();
        group.add(monitorBothRadio);
        group.add(monitorRequestOnlyRadio);
        group.add(monitorResponseOnlyRadio);

        JPanel radioPanel = new JPanel(new GridLayout(3, 1));
        radioPanel.add(monitorBothRadio);
        radioPanel.add(monitorRequestOnlyRadio);
        radioPanel.add(monitorResponseOnlyRadio);
        monitorPanel.add(radioPanel, BorderLayout.CENTER);

        // 保存按钮
        JButton saveBtn = new JButton("Save Settings");
        saveBtn.addActionListener(e -> saveSettings());
        JButton resetBtn = new JButton("Reset to Default");
        resetBtn.addActionListener(e -> resetSettings());

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(saveBtn);
        buttonPanel.add(resetBtn);

        // 组装设置面板
        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.Y_AXIS));
        centerPanel.add(keywordsPanel);
        centerPanel.add(Box.createVerticalStrut(20));
        centerPanel.add(monitorPanel);

        settingsPanel.add(centerPanel, BorderLayout.CENTER);
        settingsPanel.add(buttonPanel, BorderLayout.SOUTH);

        return settingsPanel;
    }

    /**
     * 保存设置
     */
    private void saveSettings() {
        keywords = keywordsField.getText().trim();
        if (keywords.isEmpty()) {
            keywords = "token";
            keywordsField.setText("token");
        }

        if (monitorBothRadio.isSelected()) {
            monitorMode = 0;
        } else if (monitorRequestOnlyRadio.isSelected()) {
            monitorMode = 1;
        } else if (monitorResponseOnlyRadio.isSelected()) {
            monitorMode = 2;
        }

        JOptionPane.showMessageDialog(null, "Settings saved!\nKeywords: " + keywords + "\nMonitor mode: " +
                (monitorMode == 0 ? "Both" : monitorMode == 1 ? "Request Only" : "Response Only"));
    }

    /**
     * 重置设置
     */
    private void resetSettings() {
        keywords = "token";
        monitorMode = 0;
        keywordsField.setText("token");
        monitorBothRadio.setSelected(true);
    }

    /**
     * 显示选中记录的请求和响应
     */
    private void showRequestResponse(int rowIndex) {
        if (rowIndex < 0 || rowIndex >= records.size()) {
            return;
        }

        TokenRecord record = records.get(rowIndex);

        // 如果点击的是同一行，切换关键字索引；否则重置索引
        if (rowIndex == lastClickedRow) {
            currentClickIndex++;
        } else {
            currentClickIndex = 0;
            lastClickedRow = rowIndex;
        }

        // 获取所有匹配的关键字
        String[] matchedKeywords = record.matchedKeyword != null ?
                record.matchedKeyword.split(",") : keywords.split(",");
        for (int i = 0; i < matchedKeywords.length; i++) {
            matchedKeywords[i] = matchedKeywords[i].trim();
        }

        // 循环索引
        int searchIndex = currentClickIndex % matchedKeywords.length;
        String searchWord = matchedKeywords[searchIndex];

        SwingUtilities.invokeLater(() -> {
            try {
                // 设置请求
                if (record.rawRequest != null && !record.rawRequest.isEmpty()) {
                    HttpRequest request = HttpRequest.httpRequest(record.rawRequest);
                    requestEditor.setRequest(request);
                }

                // 设置响应
                if (record.rawResponse != null && !record.rawResponse.isEmpty()) {
                    HttpResponse response = HttpResponse.httpResponse(record.rawResponse);
                    responseEditor.setResponse(response);
                } else {
                    responseEditor.setResponse(HttpResponse.httpResponse(""));
                }

                // 延迟一下，等编辑器加载完内容，搜索对应关键字
                Timer searchTimer = new Timer(100, e -> {
                    setSearchText(requestEditor.uiComponent(), searchWord);
                    setSearchText(responseEditor.uiComponent(), searchWord);
                });
                searchTimer.setRepeats(false);
                searchTimer.start();

            } catch (Exception ex) {
                api.logging().logToError("[TokenScanner] Display error: " + ex.getMessage());
            }
        });
    }

    /**
     * 在编辑器中搜索文本
     */
    private void setSearchText(Component component, String searchText) {
        if (component == null) return;

        try {
            List<JTextField> textFields = new java.util.ArrayList<>();
            findTextFields(component, textFields, 0);

            for (int i = 0; i < textFields.size(); i++) {
                JTextField field = textFields.get(i);
                Rectangle bounds = field.getBounds();
                if (bounds.width >= 50 && bounds.width <= 1200) {
                    field.setText(searchText);
                    field.getCaret().setDot(searchText.length());
                    field.dispatchEvent(new KeyEvent(field, KeyEvent.KEY_PRESSED, System.currentTimeMillis(), 0, KeyEvent.VK_ENTER, KeyEvent.CHAR_UNDEFINED));
                    field.dispatchEvent(new KeyEvent(field, KeyEvent.KEY_RELEASED, System.currentTimeMillis(), 0, KeyEvent.VK_ENTER, KeyEvent.CHAR_UNDEFINED));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[TokenScanner] Search error: " + e.getMessage());
        }
    }

    /**
     * 递归查找所有JTextField
     */
    private void findTextFields(Component component, List<JTextField> result, int depth) {
        if (component == null || depth > 20) return;

        if (component instanceof JTextField) {
            result.add((JTextField) component);
        }

        if (component instanceof Container) {
            for (Component child : ((Container) component).getComponents()) {
                findTextFields(child, result, depth + 1);
            }
        }
    }

    /**
     * 清空编辑器
     */
    private void clearEditors() {
        SwingUtilities.invokeLater(() -> {
            try {
                requestEditor.setRequest(HttpRequest.httpRequest(""));
                responseEditor.setResponse(HttpResponse.httpResponse(""));
            } catch (Exception ex) {
                // 忽略
            }
        });
    }

    /**
     * Token记录数据类
     */
    private static class TokenRecord {
        final int id;
        final String source;
        final String host;
        final String method;
        final String url;
        final int statusCode;
        final int length;
        final String mimeType;
        final String ip;
        final String timestamp;
        final burp.api.montoya.http.HttpService httpService;
        final String rawRequest;
        final String rawResponse;
        final String matchedKeyword;

        TokenRecord(int id, String source, String host, String method, String url, int statusCode,
                    int length, String mimeType, String ip, String timestamp,
                    burp.api.montoya.http.HttpService httpService,
                    String rawRequest, String rawResponse, String matchedKeyword) {
            this.id = id;
            this.source = source;
            this.host = host;
            this.method = method;
            this.url = url;
            this.statusCode = statusCode;
            this.length = length;
            this.mimeType = mimeType;
            this.ip = ip;
            this.timestamp = timestamp;
            this.httpService = httpService;
            this.rawRequest = rawRequest;
            this.rawResponse = rawResponse;
            this.matchedKeyword = matchedKeyword;
        }
    }
}
