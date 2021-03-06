#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QApplication>
#include "utilwidgets.h"
#include "theme.h"

using namespace std;


Subheading::Subheading(const QString& name, const QColor& color, bool large)
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);

	m_label = new QLabel(name);
	if (large)
		m_label->setFont(fontOfRelativeSize(1.2f, QFont::DemiBold));
	else
		m_label->setFont(fontOfRelativeSize(1.0f, QFont::DemiBold));
	QPalette headerPalette(palette());
	headerPalette.setColor(QPalette::WindowText, color);
	headerPalette.setColor(QPalette::Text, color);
	m_label->setPalette(headerPalette);
	layout->addWidget(m_label);

	QFrame* frame = new QFrame();
	frame->setFrameShape(QFrame::HLine);
	frame->setFrameShadow(QFrame::Plain);
	QPalette framePalette(palette());
	framePalette.setColor(QPalette::WindowText, color.darker());
	framePalette.setColor(QPalette::Text, color.darker());
	frame->setPalette(framePalette);
	layout->addWidget(frame);

	setLayout(layout);
}


void Subheading::setName(const QString& name)
{
	m_label->setText(name);
}


Heading::Heading(const QString& name): Subheading(name, Theme::blue, true)
{
}


ThinLabel::ThinLabel(const QString& text): QLabel(text)
{
	setFont(fontOfRelativeSize(0.9f, QFont::Thin));
}


ClickableLabel::ClickableLabel(const QString& text, QColor defaultColor, QColor hoverColor,
	const function<void()>& func): QLabel(text), m_onClick(func),
	m_defaultColor(defaultColor), m_hoverColor(hoverColor)
{
	QPalette pal = palette();
	pal.setColor(QPalette::WindowText, m_defaultColor);
	pal.setColor(QPalette::Text, m_defaultColor);
	setPalette(pal);

	m_hoverTimer = new QTimer(this);
	m_hoverTimer->setSingleShot(true);
	m_hoverTimer->setInterval(500);
	connect(m_hoverTimer, &QTimer::timeout, this, &ClickableLabel::hoverTooltip);

	setMouseTracking(true);
}


void ClickableLabel::mousePressEvent(QMouseEvent*)
{
	m_onClick();
}


void ClickableLabel::mouseMoveEvent(QMouseEvent*)
{
	m_hoverTimer->stop();
	if (m_tooltip)
		m_hoverTimer->start();
}


void ClickableLabel::enterEvent(QEvent*)
{
	QPalette pal = palette();
	pal.setColor(QPalette::WindowText, m_hoverColor);
	pal.setColor(QPalette::Text, m_hoverColor);
	setPalette(pal);
	if (m_usePictures)
		setPicture(m_hoverPicture);
}


void ClickableLabel::leaveEvent(QEvent*)
{
	QPalette pal = palette();
	pal.setColor(QPalette::WindowText, m_defaultColor);
	pal.setColor(QPalette::Text, m_defaultColor);
	setPalette(pal);
	if (m_usePictures)
		setPicture(m_normalPicture);
	m_hoverTimer->stop();
}


void ClickableLabel::hoverTooltip()
{
	if (m_tooltip)
		m_tooltip();
}


void ClickableLabel::setColors(QColor defaultColor, QColor hoverColor)
{
	m_defaultColor = defaultColor;
	m_hoverColor = hoverColor;
	QPalette pal = palette();
	pal.setColor(QPalette::WindowText, m_defaultColor);
	pal.setColor(QPalette::Text, m_defaultColor);
	setPalette(pal);
}


void ClickableLabel::setPictures(QPicture normalPicture, QPicture hoverPicture)
{
	m_normalPicture = normalPicture;
	m_hoverPicture = hoverPicture;
	m_usePictures = true;
	setPicture(m_normalPicture);
}


void ClickableLabel::setTooltipFunction(const function<void()>& func)
{
	m_tooltip = func;
	m_hoverTimer->stop();
}


ModeLabel::ModeLabel(const QString& text, const function<void()>& func):
	QLabel(text), m_onClick(func)
{
	QPalette pal = palette();
	pal.setColor(QPalette::WindowText, Theme::disabled);
	pal.setColor(QPalette::Text, Theme::disabled);
	setPalette(pal);
	setFont(fontOfRelativeSize(1.0f, QFont::Light));
	setCursor(Qt::PointingHandCursor);
}


void ModeLabel::mousePressEvent(QMouseEvent*)
{
	m_onClick();
}


void ModeLabel::enterEvent(QEvent*)
{
	QPalette pal = palette();
	pal.setColor(QPalette::WindowText, m_active ? Theme::green : Theme::content);
	pal.setColor(QPalette::Text, m_active ? Theme::green : Theme::content);
	setPalette(pal);
}


void ModeLabel::leaveEvent(QEvent*)
{
	QPalette pal = palette();
	pal.setColor(QPalette::WindowText, m_active ? Theme::green : Theme::disabled);
	pal.setColor(QPalette::Text, m_active ? Theme::green : Theme::disabled);
	setPalette(pal);
}


void ModeLabel::setActive(bool active)
{
	m_active = active;
	setFont(fontOfRelativeSize(1.0f, active ? QFont::Bold : QFont::Light));
	QPalette pal = palette();
	pal.setColor(QPalette::WindowText, m_active ? Theme::green : Theme::disabled);
	pal.setColor(QPalette::Text, m_active ? Theme::green : Theme::disabled);
	setPalette(pal);
}


QSize ModeLabel::sizeHint() const
{
	if (m_sizeToLargest)
	{
		QFontMetrics metrics(fontOfRelativeSize(1.0f, QFont::Bold));
		return metrics.boundingRect(text()).size();
	}
	return QLabel::sizeHint();
}
