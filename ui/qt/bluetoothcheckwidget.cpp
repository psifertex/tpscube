#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QPushButton>
#include "bluetoothcheckwidget.h"

using namespace std;


BluetoothCheckWidget::BluetoothCheckWidget()
{
	QVBoxLayout* layout = new QVBoxLayout();
	layout->setContentsMargins(0, 0, 0, 0);

	m_heading = new Heading("Synchronize");
	layout->addWidget(m_heading);

	m_cubeWidget = new Cube3x3Widget();
	layout->addWidget(m_cubeWidget, 1);
	layout->addSpacing(8);

	QLabel* syncLabel = new QLabel("Does this match the state\nof your Bluetooth cube?");
	syncLabel->setAlignment(Qt::AlignVCenter | Qt::AlignCenter);
	layout->addWidget(syncLabel);
	layout->addSpacing(8);

	QHBoxLayout* buttonLayout = new QHBoxLayout();
	buttonLayout->addStretch(1);
	QPushButton* yesButton = new QPushButton("Yes");
	connect(yesButton, &QPushButton::clicked, this, &BluetoothCheckWidget::correctPushed);
	buttonLayout->addWidget(yesButton);
	QPushButton* noButton = new QPushButton("No");
	connect(noButton, &QPushButton::clicked, this, &BluetoothCheckWidget::incorrectPushed);
	buttonLayout->addWidget(noButton);
	buttonLayout->addStretch(1);

	layout->addLayout(buttonLayout);
	setLayout(layout);
}


void BluetoothCheckWidget::setCube(const shared_ptr<BluetoothCube>& cube)
{
	m_cube = cube;
	m_cubeWidget->setBluetoothCube(cube);
	m_heading->setName("Synchronize " + QString::fromStdString(m_cube->GetDevice()->GetName()));
}


void BluetoothCheckWidget::correctPushed()
{
	emit correct();
}


void BluetoothCheckWidget::incorrectPushed()
{
	m_cube->ResetToSolved();
	emit incorrect();
}
