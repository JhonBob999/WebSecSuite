#include "scraper_panel.h"
#include "ui_scraper_panel.h"

scraper_panel::scraper_panel(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::scraper_panel)
{
    ui->setupUi(this);
}

scraper_panel::~scraper_panel()
{
    delete ui;
}
