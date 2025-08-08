#ifndef SCRAPER_PANEL_H
#define SCRAPER_PANEL_H

#include <QWidget>

namespace Ui {
class scraper_panel;
}

class scraper_panel : public QWidget
{
    Q_OBJECT

public:
    explicit scraper_panel(QWidget *parent = nullptr);
    ~scraper_panel();

private:
    Ui::scraper_panel *ui;
};

#endif // SCRAPER_PANEL_H
