from src.cli.monitoring_dashboard import MonitoringDashboard


def test_alerts_use_avg_waiting_time_ms_key():
    dashboard = MonitoringDashboard()
    alerts = dashboard._generate_alerts_list(
        {
            "avg_waiting_time_ms": 700.0,
            "error_rate": 0.01,
        }
    )
    assert any("HIGH_WAIT_TIME" in alert for alert in alerts)


def test_semaphore_table_uses_avg_waiting_time_ms_key():
    dashboard = MonitoringDashboard()
    table = dashboard.create_semaphore_table(
        {
            "enabled": True,
            "max_concurrent": 5,
            "current_active": 2,
            "total_executed": 10,
            "avg_waiting_time_ms": 650.0,
            "error_rate": 0.01,
        }
    )
    rendered = "\n".join(str(col.header) for col in table.columns)
    assert "Metric" in rendered
