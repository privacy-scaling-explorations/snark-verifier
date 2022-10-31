//! Copied and modified from https://github.com/foundry-rs/foundry/blob/master/ui/src/lib.rs

use crate::loader::evm::util::executor::{CallKind, DebugStep};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
        MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ethereum_types::Address;
use revm::opcode;
use std::{
    cmp::{max, min},
    io,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    terminal::Frame,
    text::{Span, Spans, Text},
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};

pub struct Tui {
    debug_arena: Vec<(Address, Vec<DebugStep>, CallKind)>,
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    key_buffer: String,
    current_step: usize,
}

impl Tui {
    pub fn new(debug_arena: Vec<(Address, Vec<DebugStep>, CallKind)>, current_step: usize) -> Self {
        enable_raw_mode().unwrap();
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture).unwrap();
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.hide_cursor().unwrap();
        Tui {
            debug_arena,
            terminal,
            key_buffer: String::new(),
            current_step,
        }
    }

    pub fn start(mut self) {
        std::panic::set_hook(Box::new(|e| {
            disable_raw_mode().expect("Unable to disable raw mode");
            execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)
                .expect("unable to execute disable mouse capture");
            println!("{e}");
        }));
        let tick_rate = Duration::from_millis(60);

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut last_tick = Instant::now();
            loop {
                if event::poll(tick_rate - last_tick.elapsed()).unwrap() {
                    let event = event::read().unwrap();
                    if let Event::Key(key) = event {
                        if tx.send(Interrupt::KeyPressed(key)).is_err() {
                            return;
                        }
                    } else if let Event::Mouse(mouse) = event {
                        if tx.send(Interrupt::MouseEvent(mouse)).is_err() {
                            return;
                        }
                    }
                }
                if last_tick.elapsed() > tick_rate {
                    if tx.send(Interrupt::IntervalElapsed).is_err() {
                        return;
                    }
                    last_tick = Instant::now();
                }
            }
        });

        self.terminal.clear().unwrap();
        let mut draw_memory: DrawMemory = DrawMemory::default();

        let debug_call = &self.debug_arena;
        let mut opcode_list: Vec<String> = debug_call[0]
            .1
            .iter()
            .map(|step| step.pretty_opcode())
            .collect();
        let mut last_index = 0;

        let mut stack_labels = false;
        let mut mem_utf = false;
        loop {
            if last_index != draw_memory.inner_call_index {
                opcode_list = debug_call[draw_memory.inner_call_index]
                    .1
                    .iter()
                    .map(|step| step.pretty_opcode())
                    .collect();
                last_index = draw_memory.inner_call_index;
            }
            match rx.recv().unwrap() {
                Interrupt::KeyPressed(event) => match event.code {
                    KeyCode::Char('q') => {
                        disable_raw_mode().unwrap();
                        execute!(
                            self.terminal.backend_mut(),
                            LeaveAlternateScreen,
                            DisableMouseCapture
                        )
                        .unwrap();
                        return;
                    }
                    KeyCode::Char('j') | KeyCode::Down => {
                        for _ in 0..Tui::buffer_as_number(&self.key_buffer, 1) {
                            if event.modifiers.contains(KeyModifiers::CONTROL) {
                                let max_mem = (debug_call[draw_memory.inner_call_index].1
                                    [self.current_step]
                                    .memory
                                    .len()
                                    / 32)
                                    .saturating_sub(1);
                                let step = if event.modifiers.contains(KeyModifiers::ALT) {
                                    20
                                } else {
                                    1
                                };
                                if draw_memory.current_mem_startline + step < max_mem {
                                    draw_memory.current_mem_startline += step;
                                }
                            } else if self.current_step < opcode_list.len() - 1 {
                                self.current_step += 1;
                            } else if draw_memory.inner_call_index < debug_call.len() - 1 {
                                draw_memory.inner_call_index += 1;
                                self.current_step = 0;
                            }
                        }
                        self.key_buffer.clear();
                    }
                    KeyCode::Char('J') => {
                        for _ in 0..Tui::buffer_as_number(&self.key_buffer, 1) {
                            let max_stack = debug_call[draw_memory.inner_call_index].1
                                [self.current_step]
                                .stack
                                .len()
                                .saturating_sub(1);
                            if draw_memory.current_stack_startline < max_stack {
                                draw_memory.current_stack_startline += 1;
                            }
                        }
                        self.key_buffer.clear();
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        for _ in 0..Tui::buffer_as_number(&self.key_buffer, 1) {
                            if event.modifiers.contains(KeyModifiers::CONTROL) {
                                draw_memory.current_mem_startline =
                                    draw_memory.current_mem_startline.saturating_sub(1);
                            } else if self.current_step > 0 {
                                self.current_step -= 1;
                            } else if draw_memory.inner_call_index > 0 {
                                draw_memory.inner_call_index -= 1;
                                self.current_step =
                                    debug_call[draw_memory.inner_call_index].1.len() - 1;
                            }
                        }
                        self.key_buffer.clear();
                    }
                    KeyCode::Char('K') => {
                        for _ in 0..Tui::buffer_as_number(&self.key_buffer, 1) {
                            draw_memory.current_stack_startline =
                                draw_memory.current_stack_startline.saturating_sub(1);
                        }
                        self.key_buffer.clear();
                    }
                    KeyCode::Char('g') => {
                        draw_memory.inner_call_index = 0;
                        self.current_step = 0;
                        self.key_buffer.clear();
                    }
                    KeyCode::Char('G') => {
                        draw_memory.inner_call_index = debug_call.len() - 1;
                        self.current_step = debug_call[draw_memory.inner_call_index].1.len() - 1;
                        self.key_buffer.clear();
                    }
                    KeyCode::Char('c') => {
                        draw_memory.inner_call_index =
                            draw_memory.inner_call_index.saturating_sub(1);
                        self.current_step = debug_call[draw_memory.inner_call_index].1.len() - 1;
                        self.key_buffer.clear();
                    }
                    KeyCode::Char('C') => {
                        if debug_call.len() > draw_memory.inner_call_index + 1 {
                            draw_memory.inner_call_index += 1;
                            self.current_step = 0;
                        }
                        self.key_buffer.clear();
                    }
                    KeyCode::Char('s') => {
                        for _ in 0..Tui::buffer_as_number(&self.key_buffer, 1) {
                            let remaining_ops = &opcode_list[self.current_step..];
                            self.current_step += remaining_ops
                                .iter()
                                .enumerate()
                                .find_map(|(i, op)| {
                                    if i < remaining_ops.len() - 1 {
                                        match (
                                            op.contains("JUMP") && op != "JUMPDEST",
                                            &*remaining_ops[i + 1],
                                        ) {
                                            (true, "JUMPDEST") => Some(i + 1),
                                            _ => None,
                                        }
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or(opcode_list.len() - 1);
                            if self.current_step > opcode_list.len() {
                                self.current_step = opcode_list.len() - 1
                            };
                        }
                        self.key_buffer.clear();
                    }
                    KeyCode::Char('a') => {
                        for _ in 0..Tui::buffer_as_number(&self.key_buffer, 1) {
                            let prev_ops = &opcode_list[..self.current_step];
                            self.current_step = prev_ops
                                .iter()
                                .enumerate()
                                .rev()
                                .find_map(|(i, op)| {
                                    if i > 0 {
                                        match (
                                            prev_ops[i - 1].contains("JUMP")
                                                && prev_ops[i - 1] != "JUMPDEST",
                                            &**op,
                                        ) {
                                            (true, "JUMPDEST") => Some(i - 1),
                                            _ => None,
                                        }
                                    } else {
                                        None
                                    }
                                })
                                .unwrap_or_default();
                        }
                        self.key_buffer.clear();
                    }
                    KeyCode::Char('t') => {
                        stack_labels = !stack_labels;
                    }
                    KeyCode::Char('m') => {
                        mem_utf = !mem_utf;
                    }
                    KeyCode::Char(other) => match other {
                        '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' => {
                            self.key_buffer.push(other);
                        }
                        _ => {
                            self.key_buffer.clear();
                        }
                    },
                    _ => {
                        self.key_buffer.clear();
                    }
                },
                Interrupt::MouseEvent(event) => match event.kind {
                    MouseEventKind::ScrollUp => {
                        if self.current_step > 0 {
                            self.current_step -= 1;
                        } else if draw_memory.inner_call_index > 0 {
                            draw_memory.inner_call_index -= 1;
                            draw_memory.current_mem_startline = 0;
                            draw_memory.current_stack_startline = 0;
                            self.current_step =
                                debug_call[draw_memory.inner_call_index].1.len() - 1;
                        }
                    }
                    MouseEventKind::ScrollDown => {
                        if self.current_step < opcode_list.len() - 1 {
                            self.current_step += 1;
                        } else if draw_memory.inner_call_index < debug_call.len() - 1 {
                            draw_memory.inner_call_index += 1;
                            draw_memory.current_mem_startline = 0;
                            draw_memory.current_stack_startline = 0;
                            self.current_step = 0;
                        }
                    }
                    _ => {}
                },
                Interrupt::IntervalElapsed => {}
            }
            let current_step = self.current_step;
            self.terminal
                .draw(|f| {
                    Tui::draw_layout(
                        f,
                        debug_call[draw_memory.inner_call_index].0,
                        &debug_call[draw_memory.inner_call_index].1[..],
                        &opcode_list,
                        current_step,
                        &mut draw_memory,
                        stack_labels,
                        mem_utf,
                    )
                })
                .unwrap();
        }
    }

    fn buffer_as_number(buffer: &str, default_value: usize) -> usize {
        if let Ok(num) = buffer.parse() {
            if num >= 1 {
                num
            } else {
                default_value
            }
        } else {
            default_value
        }
    }

    fn draw_layout<B: Backend>(
        f: &mut Frame<B>,
        address: Address,
        debug_steps: &[DebugStep],
        opcode_list: &[String],
        current_step: usize,
        draw_memory: &mut DrawMemory,
        stack_labels: bool,
        mem_utf: bool,
    ) {
        let total_size = f.size();
        if total_size.width < 225 {
            Tui::vertical_layout(
                f,
                address,
                debug_steps,
                opcode_list,
                current_step,
                draw_memory,
                stack_labels,
                mem_utf,
            );
        } else {
            Tui::square_layout(
                f,
                address,
                debug_steps,
                opcode_list,
                current_step,
                draw_memory,
                stack_labels,
                mem_utf,
            );
        }
    }

    fn vertical_layout<B: Backend>(
        f: &mut Frame<B>,
        address: Address,
        debug_steps: &[DebugStep],
        opcode_list: &[String],
        current_step: usize,
        draw_memory: &mut DrawMemory,
        stack_labels: bool,
        mem_utf: bool,
    ) {
        let total_size = f.size();
        if let [app, footer] = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Ratio(98, 100), Constraint::Ratio(2, 100)].as_ref())
            .split(total_size)[..]
        {
            if let [op_pane, stack_pane, memory_pane] = Layout::default()
                .direction(Direction::Vertical)
                .constraints(
                    [
                        Constraint::Ratio(1, 3),
                        Constraint::Ratio(1, 3),
                        Constraint::Ratio(1, 3),
                    ]
                    .as_ref(),
                )
                .split(app)[..]
            {
                Tui::draw_footer(f, footer);
                Tui::draw_op_list(
                    f,
                    address,
                    debug_steps,
                    opcode_list,
                    current_step,
                    draw_memory,
                    op_pane,
                );
                Tui::draw_stack(
                    f,
                    debug_steps,
                    current_step,
                    stack_pane,
                    stack_labels,
                    draw_memory,
                );
                Tui::draw_memory(
                    f,
                    debug_steps,
                    current_step,
                    memory_pane,
                    mem_utf,
                    draw_memory,
                );
            } else {
                panic!("unable to create vertical panes")
            }
        } else {
            panic!("unable to create footer / app")
        }
    }

    fn square_layout<B: Backend>(
        f: &mut Frame<B>,
        address: Address,
        debug_steps: &[DebugStep],
        opcode_list: &[String],
        current_step: usize,
        draw_memory: &mut DrawMemory,
        stack_labels: bool,
        mem_utf: bool,
    ) {
        let total_size = f.size();

        if let [app, footer] = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Ratio(98, 100), Constraint::Ratio(2, 100)].as_ref())
            .split(total_size)[..]
        {
            if let [left_pane, right_pane] = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)].as_ref())
                .split(app)[..]
            {
                if let [stack_pane, memory_pane] = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Ratio(2, 5), Constraint::Ratio(3, 5)].as_ref())
                    .split(right_pane)[..]
                {
                    Tui::draw_footer(f, footer);
                    Tui::draw_op_list(
                        f,
                        address,
                        debug_steps,
                        opcode_list,
                        current_step,
                        draw_memory,
                        left_pane,
                    );
                    Tui::draw_stack(
                        f,
                        debug_steps,
                        current_step,
                        stack_pane,
                        stack_labels,
                        draw_memory,
                    );
                    Tui::draw_memory(
                        f,
                        debug_steps,
                        current_step,
                        memory_pane,
                        mem_utf,
                        draw_memory,
                    );
                } else {
                    panic!("Couldn't generate horizontal split layout 1:2.");
                }
            } else {
                panic!("Couldn't generate vertical split layout 1:2.");
            }
        } else {
            panic!("Couldn't generate application & footer")
        }
    }

    fn draw_footer<B: Backend>(f: &mut Frame<B>, area: Rect) {
        let block_controls = Block::default();

        let text_output = Text::from(Span::styled(
            "[q]: quit | [k/j]: prev/next op | [a/s]: prev/next jump | [c/C]: prev/next call | [g/G]: start/end | [t]: toggle stack labels | [m]: toggle memory decoding | [shift + j/k]: scroll stack | [ctrl + j/k]: scroll memory",
            Style::default().add_modifier(Modifier::DIM)
        ));
        let paragraph = Paragraph::new(text_output)
            .block(block_controls)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: false });
        f.render_widget(paragraph, area);
    }

    fn draw_op_list<B: Backend>(
        f: &mut Frame<B>,
        address: Address,
        debug_steps: &[DebugStep],
        opcode_list: &[String],
        current_step: usize,
        draw_memory: &mut DrawMemory,
        area: Rect,
    ) {
        let block_source_code = Block::default()
            .title(format!(
                "Address: {:?} | PC: {} | Gas used in call: {}",
                address,
                if let Some(step) = debug_steps.get(current_step) {
                    step.pc.to_string()
                } else {
                    "END".to_string()
                },
                debug_steps[current_step].total_gas_used,
            ))
            .borders(Borders::ALL);
        let mut text_output: Vec<Spans> = Vec::new();

        let display_start;

        let height = area.height as i32;
        let extra_top_lines = height / 2;
        let prev_start = draw_memory.current_startline;
        let abs_min_start = 0;
        let abs_max_start = (opcode_list.len() as i32 - 1) - (height / 2);
        let mut min_start = max(
            current_step as i32 - height + extra_top_lines,
            abs_min_start,
        ) as usize;

        let mut max_start = max(
            min(current_step as i32 - extra_top_lines, abs_max_start),
            abs_min_start,
        ) as usize;

        if min_start > max_start {
            std::mem::swap(&mut min_start, &mut max_start);
        }

        if prev_start < min_start {
            display_start = min_start;
        } else if prev_start > max_start {
            display_start = max_start;
        } else {
            display_start = prev_start;
        }
        draw_memory.current_startline = display_start;

        let max_pc_len = debug_steps
            .iter()
            .fold(0, |max_val, val| val.pc.max(max_val))
            .to_string()
            .len();

        let mut add_new_line = |line_number| {
            let bg_color = if line_number == current_step {
                Color::DarkGray
            } else {
                Color::Reset
            };

            let line_number_format = if line_number == current_step {
                let step: &DebugStep = &debug_steps[line_number];
                format!("{:0>max_pc_len$x}|▶", step.pc, max_pc_len = max_pc_len)
            } else if line_number < debug_steps.len() {
                let step: &DebugStep = &debug_steps[line_number];
                format!("{:0>max_pc_len$x}| ", step.pc, max_pc_len = max_pc_len)
            } else {
                "END CALL".to_string()
            };

            if let Some(op) = opcode_list.get(line_number) {
                text_output.push(Spans::from(Span::styled(
                    format!("{line_number_format}{op}"),
                    Style::default().fg(Color::White).bg(bg_color),
                )));
            } else {
                text_output.push(Spans::from(Span::styled(
                    line_number_format,
                    Style::default().fg(Color::White).bg(bg_color),
                )));
            }
        };
        for number in display_start..opcode_list.len() {
            add_new_line(number);
        }
        add_new_line(opcode_list.len());
        let paragraph = Paragraph::new(text_output)
            .block(block_source_code)
            .wrap(Wrap { trim: true });
        f.render_widget(paragraph, area);
    }

    fn draw_stack<B: Backend>(
        f: &mut Frame<B>,
        debug_steps: &[DebugStep],
        current_step: usize,
        area: Rect,
        stack_labels: bool,
        draw_memory: &mut DrawMemory,
    ) {
        let stack = &debug_steps[current_step].stack;
        let stack_space = Block::default()
            .title(format!("Stack: {}", stack.len()))
            .borders(Borders::ALL);
        let min_len = usize::max(format!("{}", stack.len()).len(), 2);

        let indices_affected = stack_indices_affected(debug_steps[current_step].instruction.0);

        let text: Vec<Spans> = stack
            .iter()
            .rev()
            .enumerate()
            .skip(draw_memory.current_stack_startline)
            .map(|(i, stack_item)| {
                let affected = indices_affected
                    .iter()
                    .find(|(affected_index, _name)| *affected_index == i);

                let mut words: Vec<Span> = (0..32)
                    .into_iter()
                    .rev()
                    .map(|i| stack_item.byte(i))
                    .map(|byte| {
                        Span::styled(
                            format!("{:02x} ", byte),
                            if affected.is_some() {
                                Style::default().fg(Color::Cyan)
                            } else if byte == 0 {
                                Style::default().add_modifier(Modifier::DIM)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        )
                    })
                    .collect();

                if stack_labels {
                    if let Some((_, name)) = affected {
                        words.push(Span::raw(format!("| {name}")));
                    } else {
                        words.push(Span::raw("| ".to_string()));
                    }
                }

                let mut spans = vec![Span::styled(
                    format!("{:0min_len$}| ", i, min_len = min_len),
                    Style::default().fg(Color::White),
                )];
                spans.extend(words);
                spans.push(Span::raw("\n"));

                Spans::from(spans)
            })
            .collect();

        let paragraph = Paragraph::new(text)
            .block(stack_space)
            .wrap(Wrap { trim: true });
        f.render_widget(paragraph, area);
    }

    fn draw_memory<B: Backend>(
        f: &mut Frame<B>,
        debug_steps: &[DebugStep],
        current_step: usize,
        area: Rect,
        mem_utf8: bool,
        draw_mem: &mut DrawMemory,
    ) {
        let memory = &debug_steps[current_step].memory;
        let stack_space = Block::default()
            .title(format!(
                "Memory (max expansion: {} bytes)",
                memory.effective_len()
            ))
            .borders(Borders::ALL);
        let memory = memory.data();
        let max_i = memory.len() / 32;
        let min_len = format!("{:x}", max_i * 32).len();

        let mut word = None;
        let mut color = None;
        let stack_len = debug_steps[current_step].stack.len();
        if stack_len > 0 {
            let w = debug_steps[current_step].stack[stack_len - 1];
            match debug_steps[current_step].instruction.0 {
                opcode::MLOAD => {
                    word = Some(w.as_usize() / 32);
                    color = Some(Color::Cyan);
                }
                opcode::MSTORE => {
                    word = Some(w.as_usize() / 32);
                    color = Some(Color::Red);
                }
                _ => {}
            }
        }

        if current_step > 0 {
            let prev_step = current_step - 1;
            let stack_len = debug_steps[prev_step].stack.len();
            if debug_steps[prev_step].instruction.0 == opcode::MSTORE {
                let prev_top = debug_steps[prev_step].stack[stack_len - 1];
                word = Some(prev_top.as_usize() / 32);
                color = Some(Color::Green);
            }
        }

        let text: Vec<Spans> = memory
            .chunks(32)
            .enumerate()
            .skip(draw_mem.current_mem_startline)
            .map(|(i, mem_word)| {
                let words: Vec<Span> = mem_word
                    .iter()
                    .map(|byte| {
                        Span::styled(
                            format!("{:02x} ", byte),
                            if let (Some(w), Some(color)) = (word, color) {
                                if i == w {
                                    Style::default().fg(color)
                                } else if *byte == 0 {
                                    Style::default().add_modifier(Modifier::DIM)
                                } else {
                                    Style::default().fg(Color::White)
                                }
                            } else if *byte == 0 {
                                Style::default().add_modifier(Modifier::DIM)
                            } else {
                                Style::default().fg(Color::White)
                            },
                        )
                    })
                    .collect();

                let mut spans = vec![Span::styled(
                    format!("{:0min_len$x}| ", i * 32, min_len = min_len),
                    Style::default().fg(Color::White),
                )];
                spans.extend(words);

                if mem_utf8 {
                    let chars: Vec<Span> = mem_word
                        .chunks(4)
                        .map(|utf| {
                            if let Ok(utf_str) = std::str::from_utf8(utf) {
                                Span::raw(utf_str.replace(char::from(0), "."))
                            } else {
                                Span::raw(".")
                            }
                        })
                        .collect();
                    spans.push(Span::raw("|"));
                    spans.extend(chars);
                }

                spans.push(Span::raw("\n"));

                Spans::from(spans)
            })
            .collect();
        let paragraph = Paragraph::new(text)
            .block(stack_space)
            .wrap(Wrap { trim: true });
        f.render_widget(paragraph, area);
    }
}

enum Interrupt {
    KeyPressed(KeyEvent),
    MouseEvent(MouseEvent),
    IntervalElapsed,
}

struct DrawMemory {
    pub current_startline: usize,
    pub inner_call_index: usize,
    pub current_mem_startline: usize,
    pub current_stack_startline: usize,
}

impl DrawMemory {
    fn default() -> Self {
        DrawMemory {
            current_startline: 0,
            inner_call_index: 0,
            current_mem_startline: 0,
            current_stack_startline: 0,
        }
    }
}

fn stack_indices_affected(op: u8) -> Vec<(usize, &'static str)> {
    match op {
        0x01 => vec![(0, "a"), (1, "b")],
        0x02 => vec![(0, "a"), (1, "b")],
        0x03 => vec![(0, "a"), (1, "b")],
        0x04 => vec![(0, "a"), (1, "b")],
        0x05 => vec![(0, "a"), (1, "b")],
        0x06 => vec![(0, "a"), (1, "b")],
        0x07 => vec![(0, "a"), (1, "b")],
        0x08 => vec![(0, "a"), (1, "b"), (2, "mod")],
        0x09 => vec![(0, "a"), (1, "b"), (2, "mod")],
        0x0a => vec![(0, "base"), (1, "exp")],
        0x0b => vec![(0, "i"), (1, "a")],
        0x10 => vec![(0, "a"), (1, "b")],
        0x11 => vec![(0, "a"), (1, "b")],
        0x12 => vec![(0, "a"), (1, "b")],
        0x13 => vec![(0, "a"), (1, "b")],
        0x14 => vec![(0, "a"), (1, "b")],
        0x15 => vec![(0, "a")],
        0x16 => vec![(0, "a"), (1, "b")],
        0x17 => vec![(0, "a"), (1, "b")],
        0x18 => vec![(0, "a"), (1, "b")],
        0x19 => vec![(0, "a")],
        0x1a => vec![(0, "i"), (1, "a")],
        0x1b => vec![(0, "shift"), (1, "a")],
        0x1c => vec![(0, "shift"), (1, "a")],
        0x1d => vec![(0, "shift"), (1, "a")],
        0x20 => vec![(0, "offset"), (1, "length")],
        0x31 => vec![(0, "address")],
        0x35 => vec![(0, "offset")],
        0x37 => vec![(0, "dst"), (1, "src"), (2, "length")],
        0x39 => vec![(0, "dst"), (1, "src"), (2, "length")],
        0x3b => vec![(0, "address")],
        0x3c => vec![(0, "address"), (1, "dst"), (2, "src"), (3, "length")],
        0x3e => vec![(0, "dst"), (1, "src"), (2, "length")],
        0x3f => vec![(0, "address")],
        0x40 => vec![(0, "number")],
        0x50 => vec![(0, "a")],
        0x51 => vec![(0, "offset")],
        0x52 => vec![(0, "offset"), (1, "a")],
        0x53 => vec![(0, "offset"), (1, "a")],
        0x54 => vec![(0, "key")],
        0x55 => vec![(0, "key"), (1, "a")],
        0x56 => vec![(0, "dst")],
        0x57 => vec![(0, "dst"), (1, "cond")],
        0x80 => vec![(0, "a")],
        0x81 => vec![(1, "a")],
        0x82 => vec![(2, "a")],
        0x83 => vec![(3, "a")],
        0x84 => vec![(4, "a")],
        0x85 => vec![(5, "a")],
        0x86 => vec![(6, "a")],
        0x87 => vec![(7, "a")],
        0x88 => vec![(8, "a")],
        0x89 => vec![(9, "a")],
        0x8a => vec![(10, "a")],
        0x8b => vec![(11, "a")],
        0x8c => vec![(12, "a")],
        0x8d => vec![(13, "a")],
        0x8e => vec![(14, "a")],
        0x8f => vec![(15, "a")],
        0x90 => vec![(0, "a"), (1, "a")],
        0x91 => vec![(0, "a"), (2, "a")],
        0x92 => vec![(0, "a"), (3, "a")],
        0x93 => vec![(0, "a"), (4, "a")],
        0x94 => vec![(0, "a"), (5, "a")],
        0x95 => vec![(0, "a"), (6, "a")],
        0x96 => vec![(0, "a"), (7, "a")],
        0x97 => vec![(0, "a"), (8, "a")],
        0x98 => vec![(0, "a"), (9, "a")],
        0x99 => vec![(0, "a"), (10, "a")],
        0x9a => vec![(0, "a"), (11, "a")],
        0x9b => vec![(0, "a"), (12, "a")],
        0x9c => vec![(0, "a"), (13, "a")],
        0x9d => vec![(0, "a"), (14, "a")],
        0x9e => vec![(0, "a"), (15, "a")],
        0x9f => vec![(0, "a"), (16, "a")],
        0xa0 => vec![(0, "offset"), (1, "length")],
        0xa1 => vec![(0, "offset"), (1, "length"), (2, "topic")],
        0xa2 => vec![(0, "offset"), (1, "length"), (2, "topic1"), (3, "topic2")],
        0xa3 => vec![
            (0, "offset"),
            (1, "length"),
            (2, "topic1"),
            (3, "topic2"),
            (4, "topic3"),
        ],
        0xa4 => vec![
            (0, "offset"),
            (1, "length"),
            (2, "topic1"),
            (3, "topic2"),
            (4, "topic3"),
            (5, "topic4"),
        ],
        0xf0 => vec![(0, "value"), (1, "offset"), (2, "length")],
        0xf1 => vec![
            (0, "gas"),
            (1, "address"),
            (2, "value"),
            (3, "cd_offset"),
            (4, "cd_length"),
            (5, "rd_offset"),
            (6, "rd_length"),
        ],
        0xf2 => vec![
            (0, "gas"),
            (1, "address"),
            (2, "value"),
            (3, "cd_offset"),
            (4, "cd_length"),
            (5, "rd_offset"),
            (6, "rd_length"),
        ],
        0xf3 => vec![(0, "offset"), (1, "length")],
        0xf4 => vec![
            (0, "gas"),
            (1, "address"),
            (2, "cd_offset"),
            (3, "cd_length"),
            (4, "rd_offset"),
            (5, "rd_length"),
        ],
        0xf5 => vec![(0, "value"), (1, "offset"), (2, "length"), (3, "salt")],
        0xfa => vec![
            (0, "gas"),
            (1, "address"),
            (2, "cd_offset"),
            (3, "cd_length"),
            (4, "rd_offset"),
            (5, "rd_length"),
        ],
        0xfd => vec![(0, "offset"), (1, "length")],
        0xff => vec![(0, "address")],
        _ => vec![],
    }
}
