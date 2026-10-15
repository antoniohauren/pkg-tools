mod package;

use adw::prelude::*;
use gtk::{gio, glib};
use std::{
    cell::{Cell, RefCell},
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

struct Ui {
    window: glib::WeakRef<adw::ApplicationWindow>,
    open: gtk::Button,
    welcome_open: gtk::Button,
    extract: gtk::Button,
    convert: gio::SimpleAction,
    pages: gtk::Stack,
    details: gtk::Box,
    info_dialog: adw::Dialog,
    all_info: gio::SimpleAction,
    artwork: gtk::Image,
    title_id: adw::ActionRow,
    version: adw::ActionRow,
    kind: adw::ActionRow,
    cancel: gtk::Button,
    cancellation: Arc<AtomicBool>,
    title: gtk::Label,
    source: adw::ActionRow,
    size: adw::ActionRow,
    content_id: adw::ActionRow,
    metadata_status: adw::ActionRow,
    metadata: gtk::TextView,
    extraction_dialog: adw::Dialog,
    extraction_status: gtk::Label,
    extraction_progress: gtk::ProgressBar,
    extraction_transfer: gtk::Label,
    spinner: gtk::Spinner,
    toasts: adw::ToastOverlay,
    path: RefCell<Option<PathBuf>>,
    busy: Cell<bool>,
    can_convert: Cell<bool>,
}

impl Ui {
    fn busy(&self, busy: bool, label: &str) {
        self.busy.set(busy);
        self.open.set_sensitive(!busy);
        self.welcome_open.set_sensitive(!busy);
        self.extract
            .set_sensitive(!busy && self.path.borrow().is_some());
        self.convert
            .set_enabled(!busy && self.path.borrow().is_some() && self.can_convert.get());
        self.spinner.set_opacity(if busy { 1.0 } else { 0.0 });
        self.spinner.set_tooltip_text(Some(label));
        self.spinner.set_spinning(busy);
    }

    fn show_extraction(&self) {
        self.cancellation.store(false, Ordering::Relaxed);
        self.cancel.set_sensitive(true);
        self.extraction_status.set_label("Preparing package…");
        self.extraction_transfer
            .set_label("Calculating output size…");
        self.extraction_progress.set_fraction(0.0);
        self.extraction_progress.set_text(Some("Preparing…"));
        self.extraction_dialog
            .present(self.window.upgrade().as_ref());
    }

    fn cancel_extraction(&self) {
        self.cancellation.store(true, Ordering::Relaxed);
        self.cancel.set_sensitive(false);
        self.extraction_status.set_label("Cancelling…");
    }

    fn update_progress(&self, written: u64, total: u64, bytes_per_second: f64) {
        let fraction = if total == 0 {
            0.0
        } else {
            written as f64 / total as f64
        };
        self.extraction_progress.set_fraction(fraction);
        self.extraction_progress
            .set_text(Some(&format!("{:.0}%", fraction * 100.0)));
        self.extraction_transfer.set_label(&format!(
            "{:.1} / {:.1} MB · {:.1} MB/s",
            written as f64 / 1_000_000.0,
            total as f64 / 1_000_000.0,
            bytes_per_second / 1_000_000.0,
        ));
        if !self.cancellation.load(Ordering::Relaxed) {
            self.extraction_status.set_label(if written == total {
                "Finishing…"
            } else {
                "Writing files…"
            });
        }
    }

    fn error(&self, title: &str, message: &str) {
        let dialog = adw::AlertDialog::builder()
            .heading(title)
            .body(message)
            .build();
        dialog.add_response("close", "Close");
        dialog.set_default_response(Some("close"));
        dialog.set_close_response("close");
        dialog.present(self.window.upgrade().as_ref());
    }

    fn choose_package(self: &Rc<Self>) {
        if self.busy.get() {
            return;
        }
        self.busy(true, "Choose a package…");
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let filter = gtk::FileFilter::new();
            filter.set_name(Some("PS3 / PS4 packages"));
            filter.add_pattern("*.pkg");
            filter.add_pattern("*.PKG");
            let all = gtk::FileFilter::new();
            all.set_name(Some("All files"));
            all.add_pattern("*");
            let filters = gio::ListStore::new::<gtk::FileFilter>();
            filters.append(&filter);
            filters.append(&all);
            let dialog = gtk::FileDialog::builder()
                .title("Open Package")
                .filters(&filters)
                .build();
            let result = dialog.open_future(ui.window.upgrade().as_ref()).await;
            ui.busy(false, "");
            match result {
                Ok(file) => ui.load(file),
                Err(e) if e.matches(gtk::DialogError::Dismissed) => {}
                Err(e) => ui.error("Could Not Open Package", &e.to_string()),
            }
        });
    }

    fn load(self: &Rc<Self>, file: gio::File) {
        if self.busy.get() {
            return;
        }
        let Some(path) = file.path() else {
            self.error(
                "Local File Required",
                "Copy the package to a local folder first.",
            );
            return;
        };
        self.busy(true, "Reading package…");
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let input = path.clone();
            let result = gio::spawn_blocking(move || package::inspect(&input)).await;
            match result {
                Ok(Ok(details)) => {
                    ui.can_convert.set(details.can_convert);
                    ui.title.set_label(&details.title);
                    ui.title_id
                        .set_subtitle(&glib::markup_escape_text(&details.title_id));
                    ui.version
                        .set_subtitle(&glib::markup_escape_text(&details.version));
                    ui.kind
                        .set_subtitle(&glib::markup_escape_text(&details.kind));
                    ui.artwork.set_icon_name(Some("package-x-generic-symbolic"));
                    if let Some(icon) = details.icon {
                        match gtk::gdk::Texture::from_bytes(&glib::Bytes::from_owned(icon)) {
                            Ok(texture) => ui.artwork.set_paintable(Some(&texture)),
                            Err(_) => ui
                                .toasts
                                .add_toast(adw::Toast::new("Game artwork could not be decoded.")),
                        }
                    }
                    ui.source
                        .set_subtitle(&glib::markup_escape_text(&path.display().to_string()));
                    ui.size.set_subtitle(&format!(
                        "{} · {} bytes",
                        glib::format_size(details.size),
                        details.size
                    ));
                    ui.content_id
                        .set_subtitle(&glib::markup_escape_text(&details.content_id));
                    ui.metadata_status.set_subtitle(&details.status);
                    ui.metadata.buffer().set_text(&details.metadata);
                    *ui.path.borrow_mut() = Some(path);
                    ui.pages.set_visible_child(&ui.details);
                    ui.all_info.set_enabled(true);
                }
                Ok(Err(e)) => ui.error("Could Not Read Package", &e),
                Err(_) => ui.error(
                    "Could Not Read Package",
                    "The background worker stopped unexpectedly.",
                ),
            }
            ui.busy(false, "");
        });
    }

    fn choose_destination(self: &Rc<Self>, converting: bool) {
        if self.busy.get() {
            return;
        }
        let Some(source) = self.path.borrow().clone() else {
            return;
        };
        self.busy(true, "Choose a destination…");
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let mut update = None;
            if converting {
                let dialog = adw::AlertDialog::builder()
                    .heading("Convert to ZAR")
                    .body("Convert the loaded base game. A matching update can be saved as a separate -UPDATE.zar archive beside it. Existing archives are never replaced.")
                    .build();
                dialog.add_response("cancel", "Cancel");
                dialog.add_response("base", "Base Only");
                dialog.add_response("update", "Choose Update…");
                dialog.set_default_response(Some("base"));
                dialog.set_close_response("cancel");
                match dialog
                    .choose_future(ui.window.upgrade().as_ref())
                    .await
                    .as_str()
                {
                    "base" => {}
                    "update" => {
                        let filter = gtk::FileFilter::new();
                        filter.set_name(Some("PS4 packages"));
                        filter.add_pattern("*.pkg");
                        filter.add_pattern("*.PKG");
                        let filters = gio::ListStore::new::<gtk::FileFilter>();
                        filters.append(&filter);
                        let picker = gtk::FileDialog::builder()
                            .title("Choose Matching Update")
                            .filters(&filters)
                            .build();
                        match picker.open_future(ui.window.upgrade().as_ref()).await {
                            Ok(file) => {
                                update = file.path();
                                if update.is_none() {
                                    ui.busy(false, "");
                                    ui.error(
                                        "Local File Required",
                                        "Choose a local update package.",
                                    );
                                    return;
                                }
                            }
                            Err(e) => {
                                ui.busy(false, "");
                                if !e.matches(gtk::DialogError::Dismissed) {
                                    ui.error("Could Not Choose Update", &e.to_string());
                                }
                                return;
                            }
                        }
                    }
                    _ => {
                        ui.busy(false, "");
                        return;
                    }
                }
            }
            let dialog = gtk::FileDialog::builder()
                .title(if converting {
                    "Save ZAR Archive"
                } else {
                    "Choose Extraction Parent Folder"
                })
                .accept_label(if converting {
                    "Convert"
                } else {
                    "Extract Here"
                })
                .build();
            let selection = if converting {
                dialog.set_initial_name(Some(
                    source
                        .with_extension("zar")
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .as_ref(),
                ));
                dialog.save_future(ui.window.upgrade().as_ref()).await
            } else {
                dialog
                    .select_folder_future(ui.window.upgrade().as_ref())
                    .await
            };
            let folder = match selection {
                Ok(folder) => folder,
                Err(e) => {
                    ui.busy(false, "");
                    if !e.matches(gtk::DialogError::Dismissed) {
                        ui.error("Could Not Choose Destination", &e.to_string());
                    }
                    return;
                }
            };
            let Some(parent) = folder.path() else {
                ui.busy(false, "");
                ui.error("Local Folder Required", "Choose a local destination.");
                return;
            };
            let destination = if converting {
                parent
            } else {
                package::destination(&source, &parent)
            };
            ui.busy(
                true,
                if converting {
                    "Converting package…"
                } else {
                    "Extracting package…"
                },
            );
            ui.extraction_dialog.set_title(if converting {
                "Converting to ZAR"
            } else {
                "Extracting Package"
            });
            ui.show_extraction();
            let cancellation = ui.cancellation.clone();
            let progress = Arc::new(Mutex::new(None));
            let worker_progress = progress.clone();
            let mut last_sample = Instant::now();
            let mut last_written = 0;
            let timer = glib::timeout_add_local(
                Duration::from_millis(250),
                glib::clone!(
                    #[weak]
                    ui,
                    #[upgrade_or]
                    glib::ControlFlow::Break,
                    move || {
                        let sample = *progress.lock().unwrap();
                        if let Some((written, total)) = sample {
                            let now = Instant::now();
                            let rate = (written - last_written) as f64
                                / now.duration_since(last_sample).as_secs_f64();
                            ui.update_progress(written, total, rate);
                            last_written = written;
                            last_sample = now;
                        } else {
                            ui.extraction_progress.pulse();
                            last_sample = Instant::now();
                        }
                        glib::ControlFlow::Continue
                    }
                ),
            );
            let output = destination.clone();
            let result = gio::spawn_blocking(move || {
                let progress = |written, total| {
                    *worker_progress.lock().unwrap() = Some((written, total));
                };
                if converting {
                    pkg_cli::convert::run_with_progress(&source, &output, update.as_deref(),
                        || cancellation.load(Ordering::Relaxed), progress)
                        .map_err(|e| e.to_string())
                } else {
                    package::extract(&source, &output, &cancellation, progress).map_err(|e| {
                        if package::was_cancelled(e.as_ref()) {
                            format!("{e}\n\nIf a partial output folder was created, remove it before retrying. Existing files were not replaced.")
                        } else {
                            e.to_string()
                        }
                    })
                }
            })
            .await;
            timer.remove();
            ui.extraction_dialog.force_close();
            ui.busy(false, "");
            match result {
                Ok(Ok(())) => {
                    let dialog = adw::AlertDialog::builder()
                        .heading(if converting {
                            "Conversion Complete"
                        } else {
                            "Extraction Complete"
                        })
                        .body(format!("Files saved to {}", destination.display()))
                        .build();
                    dialog.add_response("close", "Close");
                    dialog.add_response("show", "Open Folder");
                    dialog.set_default_response(Some("show"));
                    dialog.set_close_response("close");
                    if dialog.choose_future(ui.window.upgrade().as_ref()).await == "show" {
                        let folder = if converting {
                            destination.parent().unwrap().to_path_buf()
                        } else {
                            destination
                        };
                        let launcher = gtk::FileLauncher::new(Some(&gio::File::for_path(folder)));
                        if let Err(e) = launcher.launch_future(ui.window.upgrade().as_ref()).await {
                            ui.error("Could Not Open Folder", &e.to_string());
                        }
                    }
                }
                Ok(Err(e)) => ui.error(
                    if converting {
                        "Conversion Stopped"
                    } else {
                        "Extraction Stopped"
                    },
                    &e,
                ),
                Err(_) => ui.error(
                    "Operation Failed",
                    &format!(
                        "The worker stopped unexpectedly. Check the output at {} before retrying.",
                        destination.display()
                    ),
                ),
            }
        });
    }
}

fn build(app: &adw::Application) -> Rc<Ui> {
    let builder = gtk::Builder::from_string(include_str!(concat!(env!("OUT_DIR"), "/window.ui")));
    let window: adw::ApplicationWindow = builder.object("window").unwrap();
    window.set_application(Some(app));
    let ui = Rc::new(Ui {
        window: window.downgrade(),
        open: builder.object("open").unwrap(),
        welcome_open: builder.object("welcome_open").unwrap(),
        extract: builder.object("extract").unwrap(),
        convert: gio::SimpleAction::new("convert", None),
        pages: builder.object("pages").unwrap(),
        details: builder.object("details").unwrap(),
        info_dialog: builder.object("info_dialog").unwrap(),
        all_info: gio::SimpleAction::new("all-info", None),
        artwork: builder.object("artwork").unwrap(),
        title_id: builder.object("title_id").unwrap(),
        version: builder.object("version").unwrap(),
        kind: builder.object("kind").unwrap(),
        cancel: builder.object("cancel").unwrap(),
        cancellation: Arc::new(AtomicBool::new(false)),
        title: builder.object("package_title").unwrap(),
        source: builder.object("source").unwrap(),
        size: builder.object("size").unwrap(),
        content_id: builder.object("content_id").unwrap(),
        metadata_status: builder.object("metadata_status").unwrap(),
        metadata: builder.object("metadata").unwrap(),
        extraction_dialog: builder.object("extraction_dialog").unwrap(),
        extraction_status: builder.object("extraction_status").unwrap(),
        extraction_progress: builder.object("extraction_progress").unwrap(),
        extraction_transfer: builder.object("extraction_transfer").unwrap(),
        spinner: builder.object("spinner").unwrap(),
        toasts: builder.object("toasts").unwrap(),
        path: RefCell::new(None),
        busy: Cell::new(false),
        can_convert: Cell::new(false),
    });
    for button in [&ui.open, &ui.welcome_open] {
        button.connect_clicked(glib::clone!(
            #[weak]
            ui,
            move |_| ui.choose_package()
        ));
    }
    let drop_target = gtk::DropTarget::new(
        gtk::gdk::FileList::static_type(),
        gtk::gdk::DragAction::COPY,
    );
    drop_target.connect_drop(glib::clone!(
        #[weak]
        ui,
        #[upgrade_or]
        false,
        move |_, value, _, _| {
            if ui.busy.get() {
                return false;
            }
            let Ok(files) = value.get::<gtk::gdk::FileList>() else {
                return false;
            };
            let files = files.files();
            let [file] = files.as_slice() else {
                ui.toasts
                    .add_toast(adw::Toast::new("Drop one package at a time."));
                return false;
            };
            ui.load(file.clone());
            true
        }
    ));
    window.add_controller(drop_target);
    ui.extract.connect_clicked(glib::clone!(
        #[weak]
        ui,
        move |_| ui.choose_destination(false)
    ));
    ui.convert.set_enabled(false);
    ui.convert.connect_activate(glib::clone!(
        #[weak]
        ui,
        move |_, _| ui.choose_destination(true)
    ));
    window.add_action(&ui.convert);
    let open = gio::SimpleAction::new("open", None);
    ui.all_info.set_enabled(false);
    ui.all_info.connect_activate(glib::clone!(
        #[weak]
        ui,
        move |_, _| {
            ui.info_dialog.present(ui.window.upgrade().as_ref());
        }
    ));
    window.add_action(&ui.all_info);
    let about = gio::SimpleAction::new("about", None);
    about.connect_activate(glib::clone!(
        #[weak]
        window,
        move |_, _| {
            adw::AboutDialog::builder()
                .application_name("PKG Tools")
                .application_icon("package-x-generic")
                .version(env!("CARGO_PKG_VERSION"))
                .comments(
                    "Inspect PlayStation 4 package metadata and extract supported fake packages.",
                )
                .build()
                .present(Some(&window));
        }
    ));
    window.add_action(&about);
    let quit = gio::SimpleAction::new("quit", None);
    quit.connect_activate(glib::clone!(
        #[weak]
        app,
        move |_, _| {
            // Use close requests so active extraction keeps its window alive.
            for window in app.windows() {
                window.close();
            }
        }
    ));
    window.add_action(&quit);
    app.set_accels_for_action("win.quit", &["<Control>q"]);
    ui.cancel.connect_clicked(glib::clone!(
        #[weak]
        ui,
        move |_| {
            ui.cancel_extraction();
        }
    ));
    ui.extraction_dialog.connect_close_attempt(glib::clone!(
        #[weak]
        ui,
        move |_| {
            ui.cancel_extraction();
        }
    ));
    open.connect_activate(glib::clone!(
        #[weak]
        ui,
        move |_, _| ui.choose_package()
    ));
    window.add_action(&open);
    app.set_accels_for_action("win.open", &["<Control>o"]);
    window.connect_close_request(glib::clone!(
        #[weak]
        ui,
        #[upgrade_or]
        glib::Propagation::Proceed,
        move |_| {
            if ui.busy.get() {
                ui.toasts
                    .add_toast(adw::Toast::new("Wait for the current operation to finish."));
                glib::Propagation::Stop
            } else {
                glib::Propagation::Proceed
            }
        }
    ));
    // Keep controller alive with its window; controller holds only a weak window reference.
    window.connect_destroy({
        let ui = ui.clone();
        move |_| {
            let _ = &ui;
        }
    });
    window.present();
    ui
}

fn main() -> glib::ExitCode {
    let app = adw::Application::builder()
        .application_id("io.github.pkg_tools.PkgTools")
        .flags(gio::ApplicationFlags::HANDLES_OPEN)
        .build();
    app.connect_activate(|app| {
        if let Some(window) = app.active_window() {
            window.present();
        } else {
            build(app);
        }
    });
    app.connect_open(|app, files, _| {
        for file in files {
            build(app).load(file.clone());
        }
    });
    app.run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires a graphical session"]
    fn blueprint_window_and_package_loading() {
        adw::init().unwrap();
        let app = adw::Application::builder()
            .application_id("io.github.pkg_tools.Test")
            .build();
        app.register(None::<&gio::Cancellable>).unwrap();
        let ui = build(&app);
        assert!(!ui.extract.is_sensitive());
        assert!(!ui.convert.is_enabled());
        assert!(!ui.all_info.is_enabled());
        let path = std::env::var_os("PKG_TOOLS_TEST_PACKAGE")
            .expect("Set PKG_TOOLS_TEST_PACKAGE to a valid PS3 or PS4 game package");
        let expected = package::inspect(std::path::Path::new(&path)).unwrap();
        let controllers = ui.window.upgrade().unwrap().observe_controllers();
        let drop_target = (0..controllers.n_items())
            .find_map(|i| {
                controllers
                    .item(i)
                    .unwrap()
                    .downcast::<gtk::DropTarget>()
                    .ok()
            })
            .unwrap();
        let file = gio::File::for_path(&path);
        let drop_files = |files: &[gio::File]| {
            drop_target.emit_by_name::<bool>(
                "drop",
                &[
                    &glib::value::BoxedValue(gtk::gdk::FileList::from_array(files).to_value()),
                    &0.0_f64,
                    &0.0_f64,
                ],
            )
        };
        assert!(!drop_files(&[file.clone(), file.clone()]));
        assert!(ui.path.borrow().is_none());
        ui.busy(true, "Busy");
        assert!(!drop_files(std::slice::from_ref(&file)));
        ui.busy(false, "");
        assert!(drop_files(std::slice::from_ref(&file)));
        let context = glib::MainContext::default();
        while ui.busy.get() {
            context.iteration(true);
        }
        assert_eq!(ui.path.borrow().as_ref(), Some(&PathBuf::from(&path)));
        assert!(ui.extract.is_sensitive());
        assert_eq!(ui.convert.is_enabled(), expected.can_convert);
        assert!(!ui.title.text().is_empty());
        assert_eq!(ui.pages.visible_child(), Some(ui.details.clone().upcast()));
        if expected.icon.is_some() {
            assert!(ui.artwork.paintable().is_some());
        } else {
            assert_eq!(
                ui.artwork.icon_name().as_deref(),
                Some("package-x-generic-symbolic")
            );
        }
        assert_ne!(ui.title_id.subtitle().as_deref(), Some("Unknown"));
        assert_ne!(ui.version.subtitle().as_deref(), Some("Unknown"));
        assert!(matches!(
            ui.kind.subtitle().as_deref(),
            Some("Game" | "Patch" | "Game data / patch")
        ));
        assert!(ui.all_info.is_enabled());
        ui.all_info.activate(None);
        assert_eq!(
            ui.window.upgrade().unwrap().visible_dialog(),
            Some(ui.info_dialog.clone())
        );
        assert!(ui.info_dialog.can_close());
        assert!(ui.metadata.buffer().char_count() > 0);
        assert!(ui.info_dialog.close());
        assert_eq!(ui.pages.visible_child(), Some(ui.details.clone().upcast()));
        ui.busy(true, "Extracting package…");
        ui.show_extraction();
        assert!(!ui.extraction_dialog.can_close());
        ui.update_progress(1_000_000, 4_000_000, 2_500_000.0);
        assert_eq!(ui.extraction_progress.fraction(), 0.25);
        assert_eq!(ui.extraction_progress.text().as_deref(), Some("25%"));
        assert_eq!(ui.extraction_transfer.text(), "1.0 / 4.0 MB · 2.5 MB/s");
        ui.cancel.emit_clicked();
        assert!(ui.cancellation.load(Ordering::Relaxed));
        assert!(!ui.cancel.is_sensitive());
        ui.update_progress(2_000_000, 4_000_000, 1_000_000.0);
        assert_eq!(ui.extraction_status.text(), "Cancelling…");
        ui.extraction_dialog.force_close();
        ui.show_extraction();
        assert!(!ui.cancellation.load(Ordering::Relaxed));
        assert!(ui.cancel.is_sensitive());
        assert_eq!(ui.extraction_progress.fraction(), 0.0);
        ui.update_progress(0, 0, 0.0);
        assert!(ui.extraction_progress.fraction().is_finite());
        ui.extraction_dialog.force_close();
        ui.busy(false, "");
        ui.window.upgrade().unwrap().close();
    }
}
