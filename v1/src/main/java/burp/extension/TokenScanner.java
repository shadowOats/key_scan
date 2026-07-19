package burp.extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.lang.reflect.Method;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class TokenScanner implements BurpExtension {

    private MontoyaApi api;
    private DefaultTableModel tableModel;
    private JTable resultTable;
    private JLabel statusLabel;
    private JLabel alertLabel;
    private final List<TokenRecord> records = new CopyOnWriteArrayList<>();
    private boolean hasNewFindings = false;
    private int blinkCount = 0;
    private Timer blinkTimer;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        this.api = montoyaApi;
        api.extension().setName("Token Scanner");

        // 注册请求处理器
        api.proxy().registerRequestHandler(new ProxyRequestHandler() {
            @Override
            public ProxyRequestReceivedAction handleRequestReceived(burp.api.montoya.proxy.http.InterceptedRequest request) {
                try {
                    String requestBody = request.bodyToString();
                    String fullRequest = request.toString();
                    String content = requestBody != null ? requestBody : fullRequest;

                    if (content != null && containsToken(content)) {
                        addRecord("REQUEST",
                                request.httpService().host(),
                                request.path(),
                                request.method(),
                                extractTokenContext(content));
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
                    String responseBody = response.bodyToString();
                    String fullResponse = response.toString();
                    String content = responseBody != null ? responseBody : fullResponse;

                    if (content != null && containsToken(content)) {
                        addRecord("RESPONSE",
                                response.initiatingRequest().httpService().host(),
                                response.initiatingRequest().path(),
                                response.initiatingRequest().method(),
                                extractTokenContext(content));
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

        // 延迟1秒后开始闪烁（等待UI完全加载）
        Timer startTimer = new Timer(1000, e -> {
            api.logging().logToOutput("[TokenScanner] Starting tab blink...");
            startTabBlink();
        });
        startTimer.setRepeats(false);
        startTimer.start();
    }

    /**
     * 检查内容是否包含token关键字（不区分大小写）
     */
    private boolean containsToken(String content) {
        if (content == null || content.isEmpty()) {
            return false;
        }
        return content.toLowerCase().contains("token");
    }

    /**
     * 提取token上下文（包含关键字的前后内容）
     */
    private String extractTokenContext(String content) {
        if (content == null) {
            return "";
        }

        String lowerContent = content.toLowerCase();
        int index = lowerContent.indexOf("token");

        if (index == -1) {
            return "";
        }

        // 提取前后各50个字符作为上下文
        int start = Math.max(0, index - 50);
        int end = Math.min(content.length(), index + 55);
        String context = content.substring(start, end).replaceAll("[\\r\\n]+", " ").trim();

        // 如果太长则截断
        if (context.length() > 100) {
            context = context.substring(0, 100) + "...";
        }

        return context;
    }

    /**
     * 添加记录并更新UI
     */
    private void addRecord(String source, String host, String path, String method, String context) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));

        TokenRecord record = new TokenRecord(timestamp, source, host, method, path, context);
        records.add(record);

        // 在EDT中更新UI
        SwingUtilities.invokeLater(() -> {
            tableModel.addRow(new Object[]{
                    record.timestamp,
                    record.source,
                    record.host,
                    record.method,
                    record.path,
                    record.context
            });

            // 滚动到最新行
            resultTable.scrollRectToVisible(resultTable.getCellRect(tableModel.getRowCount() - 1, 0, true));

            // 更新状态栏
            statusLabel.setText("Found: " + records.size() + " tokens");

            // 显示警告并闪烁Tab - 每次都闪烁
            alertLabel.setVisible(true);
            alertLabel.setText("  NEW!  ");
            startTabBlink();
        });

        api.logging().logToOutput("[TokenScanner] Token found in " + source + " - " + host + path);
    }

    /**
     * 通过反射高亮Tab标题
     */
    private void highlightTab(String tabTitle, Color color) {
        try {
            // 遍历所有窗口
            Window[] windows = Window.getWindows();
            api.logging().logToOutput("[TokenScanner] Found " + windows.length + " windows");
            for (Window window : windows) {
                api.logging().logToOutput("[TokenScanner] Window: " + window.getClass().getName());
                findAndHighlightTab(window, tabTitle, color, 0);
            }
        } catch (Exception e) {
            api.logging().logToError("[TokenScanner] Tab highlight error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 递归遍历组件树查找并高亮
     */
    private void findAndHighlightTab(Component component, String tabTitle, Color color, int depth) {
        if (component == null || depth > 20) return;

        // 检查是否是JTabbedPane
        if (component instanceof JTabbedPane) {
            JTabbedPane tabbedPane = (JTabbedPane) component;
            for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                if (tabTitle.equals(tabbedPane.getTitleAt(i))) {
                    tabbedPane.setBackgroundAt(i, color);
                    return;
                }
            }
        }

        // 递归遍历子组件
        if (component instanceof Container) {
            for (Component child : ((Container) component).getComponents()) {
                findAndHighlightTab(child, tabTitle, color, depth + 1);
            }
        }
    }

    /**
     * 重置Tab颜色
     */
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

    /**
     * 递归重置组件颜色
     */
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

    /**
     * 闪烁Tab标题提醒用户
     */
    private void startTabBlink() {
        // 停止之前的定时器
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

            if (blinkCount >= 10) { // 闪烁4秒后停止，恢复原色
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
        JPanel mainPanel = new JPanel(new BorderLayout());

        // 创建表格
        String[] columnNames = {"Time", "Source", "Host", "Method", "Path", "Context"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        resultTable = new JTable(tableModel);
        resultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultTable.setAutoCreateRowSorter(true);
        resultTable.getColumnModel().getColumn(0).setPreferredWidth(70);   // Time
        resultTable.getColumnModel().getColumn(1).setPreferredWidth(70);   // Source
        resultTable.getColumnModel().getColumn(2).setPreferredWidth(150);  // Host
        resultTable.getColumnModel().getColumn(3).setPreferredWidth(50);   // Method
        resultTable.getColumnModel().getColumn(4).setPreferredWidth(200);  // Path
        resultTable.getColumnModel().getColumn(5).setPreferredWidth(300);  // Context

        // 添加右键菜单
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("Copy Context");
        copyItem.addActionListener(e -> {
            int row = resultTable.getSelectedRow();
            if (row >= 0) {
                String context = (String) tableModel.getValueAt(row, 5);
                java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(context);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
            }
        });
        JMenuItem clearItem = new JMenuItem("Clear All");
        clearItem.addActionListener(e -> {
            tableModel.setRowCount(0);
            records.clear();
            statusLabel.setText("Found: 0 tokens");
            alertLabel.setVisible(false);
            hasNewFindings = false;
            resetTabColor("Token Scanner");
        });
        popupMenu.add(copyItem);
        popupMenu.addSeparator();
        popupMenu.add(clearItem);
        resultTable.setComponentPopupMenu(popupMenu);

        // 滚动面板
        JScrollPane scrollPane = new JScrollPane(resultTable);
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        // 底部状态栏
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        // 警告标签（闪烁提醒）
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
            statusLabel.setText("Found: 0 tokens");
            alertLabel.setVisible(false);
            hasNewFindings = false;
            resetTabColor("Token Scanner");
        });
        bottomPanel.add(clearBtn);

        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        // 注册Tab
        api.userInterface().registerSuiteTab("Token Scanner", mainPanel);
    }

    /**
     * Token记录数据类
     */
    private static class TokenRecord {
        final String timestamp;
        final String source;
        final String host;
        final String method;
        final String path;
        final String context;

        TokenRecord(String timestamp, String source, String host, String method, String path, String context) {
            this.timestamp = timestamp;
            this.source = source;
            this.host = host;
            this.method = method;
            this.path = path;
            this.context = context;
        }
    }
}
