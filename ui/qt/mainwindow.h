#include <QtWidgets/QMainWindow>
#include <QtWidgets/QStackedWidget>

class TopBar;
class TimerMode;
class HistoryMode;
class GraphMode;
class SettingsMode;

class MainWindow: public QMainWindow
{
	Q_OBJECT

	TopBar* m_topBar;
	QStackedWidget* m_stackedWidget;
	TimerMode* m_timerMode;
	int m_timerModeIndex;
	HistoryMode* m_historyMode;
	int m_historyModeIndex;
	GraphMode* m_graphMode;
	int m_graphModeIndex;
	SettingsMode* m_settingsMode;
	int m_settingsModeIndex;

	static MainWindow* m_instance;

private slots:
	void timerStarting();
	void timerStopping();
	void showTimer();
	void showHistory();
	void showGraphs();
	void showAlgorithms();
	void showSettings();
	void connectToBluetoothCube();
	void disconnectFromBluetoothCube();
	void bluetoothCubeError(QString name, QString msg);
	void paste();

protected:
	virtual void keyPressEvent(QKeyEvent* event) override;
	virtual void keyReleaseEvent(QKeyEvent* event) override;

public:
	MainWindow();
	~MainWindow();

	static MainWindow* instance();
};
