//! Live TUI dashboard for grclient.
//!
//! Run alongside the smart-routing capture loop:
//!   .\grclient.exe --config client.toml --tui
//!
//! Shows three panels updated every 250ms:
//!   1. Bridges — name, endpoint, measured client→bridge RTT, in-flight sessions
//!   2. Route decisions (recent) — destination, AWS region, direct vs via-bridge
//!      RTTs, chosen path
//!   3. Capture stats — outbound rewrites, inbound rewrites, drops, active flows
//!
//! q or Esc to quit.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Terminal,
};

use crate::router::{DecisionLog, Route, Router};
#[cfg(windows)]
use gr_capture::WinDivertCapture;

pub fn run(
    router: Arc<Router>,
    #[cfg(windows)] capture: Option<Arc<WinDivertCapture>>,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(
        &mut terminal,
        router,
        #[cfg(windows)]
        capture,
    );

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    router: Arc<Router>,
    #[cfg(windows)] capture: Option<Arc<WinDivertCapture>>,
) -> anyhow::Result<()> {
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(250);

    loop {
        terminal.draw(|f| {
            draw_dashboard(
                f,
                &router,
                #[cfg(windows)]
                &capture,
            )
        })?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_millis(0));
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        _ => {}
                    }
                }
            }
        }
        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }
}

fn draw_dashboard(
    f: &mut ratatui::Frame,
    router: &Router,
    #[cfg(windows)] capture: &Option<Arc<WinDivertCapture>>,
) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // header bar
            Constraint::Length(7),  // bridges
            Constraint::Min(8),     // route decisions
            Constraint::Length(5),  // stats
            Constraint::Length(1),  // footer keybindings
        ])
        .split(area);

    draw_header(f, chunks[0]);
    draw_bridges(f, chunks[1], router);
    draw_decisions(f, chunks[2], router);
    #[cfg(windows)]
    draw_stats(f, chunks[3], capture, router);
    #[cfg(not(windows))]
    draw_stats_stub(f, chunks[3]);
    draw_footer(f, chunks[4]);
}

fn draw_header(f: &mut ratatui::Frame, area: Rect) {
    let line = Line::from(vec![
        " lowping ".bg(Color::Cyan).fg(Color::Black).bold(),
        " live route picker ".dim(),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_footer(f: &mut ratatui::Frame, area: Rect) {
    let line = Line::from(vec![
        Span::styled(" q ", Style::default().bg(Color::DarkGray).fg(Color::White)),
        " quit  ".into(),
        Span::styled(" updates 4×/sec ", Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_bridges(f: &mut ratatui::Frame, area: Rect, router: &Router) {
    let pings = router.client_rtt_snapshot();
    let header = Row::new(vec![
        Cell::from("name").bold(),
        Cell::from("endpoint").bold(),
        Cell::from("client→bridge").bold().style(Style::default().fg(Color::Cyan)),
        Cell::from("listen").bold(),
    ]);
    let rows: Vec<Row> = router
        .bridges()
        .iter()
        .map(|b| {
            let rtt = pings.get(&b.name).copied();
            let rtt_text = match rtt {
                Some(r) => format!("{r:5.1} ms"),
                None => "  --   ".into(),
            };
            let rtt_style = match rtt {
                Some(r) if r < 30.0 => Style::default().fg(Color::Green),
                Some(r) if r < 60.0 => Style::default().fg(Color::Yellow),
                Some(_) => Style::default().fg(Color::Red),
                None => Style::default().fg(Color::DarkGray),
            };
            Row::new(vec![
                Cell::from(b.name.clone()).style(Style::default().bold()),
                Cell::from(b.endpoint.to_string()),
                Cell::from(rtt_text).style(rtt_style),
                Cell::from(format!(":{}", b.listen_port)).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(12),
        Constraint::Length(28),
        Constraint::Length(15),
        Constraint::Length(8),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(" bridges ", Style::default().fg(Color::Cyan).bold())),
        );
    f.render_widget(table, area);
}

fn draw_decisions(f: &mut ratatui::Frame, area: Rect, router: &Router) {
    let recent = router.recent_decisions(area.height.saturating_sub(3) as usize);
    let header = Row::new(vec![
        Cell::from("when").bold(),
        Cell::from("destination").bold(),
        Cell::from("region").bold(),
        Cell::from("direct").bold(),
        Cell::from("via bridge").bold(),
        Cell::from("→ route").bold(),
    ]);
    let rows: Vec<Row> = recent
        .iter()
        .map(|d| decision_row(d))
        .collect();

    let widths = [
        Constraint::Length(6),
        Constraint::Length(24),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Length(20),
    ];
    let title = format!(" route decisions ({} cached, {} recent) ",
        router.cache_size(), recent.len());
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(title, Style::default().fg(Color::Cyan).bold())),
        );
    let mut state = TableState::default();
    f.render_stateful_widget(table, area, &mut state);
}

fn decision_row(d: &DecisionLog) -> Row<'static> {
    let age = d.at.elapsed();
    let when = if age < Duration::from_secs(60) {
        format!("{}s", age.as_secs())
    } else if age < Duration::from_secs(3600) {
        format!("{}m", age.as_secs() / 60)
    } else {
        format!("{}h", age.as_secs() / 3600)
    };
    let dest = d.dest.to_string();
    let region = d.region.clone().unwrap_or_else(|| "-".into());
    let direct = if d.direct_rtt_ms.is_finite() {
        format!("{:5.1}ms", d.direct_rtt_ms)
    } else {
        "  --  ".into()
    };
    let via = if d.via_bridge_rtt_ms.is_finite() {
        format!("{:5.1}ms", d.via_bridge_rtt_ms)
    } else {
        "  --  ".into()
    };
    let (route_text, route_style) = match d.route {
        Route::Direct => (
            "direct".to_string(),
            Style::default().fg(Color::Gray),
        ),
        Route::ViaBridge(_) => {
            let name = d.bridge_name.clone().unwrap_or_default();
            (
                format!("→ {name}"),
                Style::default().fg(Color::Green).bold(),
            )
        }
    };
    Row::new(vec![
        Cell::from(when).style(Style::default().fg(Color::DarkGray)),
        Cell::from(dest),
        Cell::from(region).style(Style::default().fg(Color::Magenta)),
        Cell::from(direct),
        Cell::from(via),
        Cell::from(route_text).style(route_style),
    ])
}

#[cfg(windows)]
fn draw_stats(f: &mut ratatui::Frame, area: Rect, capture: &Option<Arc<WinDivertCapture>>, _router: &Router) {
    use gr_capture::Redirector;
    let stats = capture.as_ref().map(|c| c.stats()).unwrap_or_default();
    let lines = vec![
        Line::from(vec![
            "outbound rewrites: ".into(),
            Span::styled(stats.outbound_redirected.to_string(), Style::default().fg(Color::Green).bold()),
            "    inbound rewrites: ".into(),
            Span::styled(stats.inbound_rewritten.to_string(), Style::default().fg(Color::Green).bold()),
        ]),
        Line::from(vec![
            "dropped (unparseable): ".into(),
            Span::styled(stats.dropped_unparseable.to_string(), Style::default().fg(Color::Yellow)),
            "    active flows: ".into(),
            Span::styled(stats.active_flows.to_string(), Style::default().fg(Color::Cyan).bold()),
        ]),
        Line::from(if capture.is_some() {
            vec!["capture: ".into(), Span::styled("ARMED", Style::default().fg(Color::Green).bold())]
        } else {
            vec!["capture: ".into(), Span::styled("not started", Style::default().fg(Color::Red))]
        }),
    ];
    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" capture stats ", Style::default().fg(Color::Cyan).bold())),
    );
    f.render_widget(p, area);
}

#[cfg(not(windows))]
fn draw_stats_stub(f: &mut ratatui::Frame, area: Rect) {
    let p = Paragraph::new("(capture stats: Windows-only)").block(
        Block::default().borders(Borders::ALL).title(" stats "),
    );
    f.render_widget(p, area);
}
