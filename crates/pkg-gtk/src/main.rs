mod package;
mod ps4_send;

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
    open: gio::SimpleAction,
    welcome_open: gtk::Button,
    welcome: adw::StatusPage,
    extract: gtk::Button,
    convert: gio::SimpleAction,
    send_ps4: gio::SimpleAction,
    send_batch: gio::SimpleAction,
    link_rap: gio::SimpleAction,
    liberate: gio::SimpleAction,
    rap_source: adw::ActionRow,
    rap: RefCell<Option<PathBuf>>,
    pages: gtk::Stack,
    details: adw::NavigationSplitView,
    navigation_list: gtk::ListBox,
    navigation_toggle: gtk::Button,
    task_pages: gtk::Stack,
    summary_page: gtk::ScrolledWindow,
    send_page: adw::StatusPage,
    send_address: gtk::Entry,
    extract_page: adw::StatusPage,
    convert_page: adw::StatusPage,
    info_page: gtk::ScrolledWindow,
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
    details_data: RefCell<Option<package::Details>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Operation {
    Extract,
    Convert,
    Liberate,
}

impl Ui {
    fn show_task(&self, index: i32) {
        if index == 0 && self.path.borrow().is_none() {
            self.pages.set_visible_child(&self.welcome);
            self.details.set_show_content(true);
            return;
        }
        let page: &gtk::Widget = match index {
            0 => self.summary_page.upcast_ref(),
            1 => self.send_page.upcast_ref(),
            2 => self.extract_page.upcast_ref(),
            3 => self.convert_page.upcast_ref(),
            _ => self.info_page.upcast_ref(),
        };
        self.task_pages.set_visible_child(page);
        self.pages.set_visible_child(&self.task_pages);
        self.details.set_show_content(true);
    }

    fn toggle_sidebar(&self) {
        if self.details.is_collapsed() {
            if self
                .window
                .upgrade()
                .is_some_and(|window| window.width() > 600)
            {
                self.details.set_collapsed(false);
            } else {
                self.details.set_show_content(!self.details.shows_content());
            }
        } else {
            self.details.set_collapsed(true);
            self.details.set_show_content(true);
        }
    }

    fn update_sidebar_toggle(&self) {
        let tooltip = if !self.details.is_collapsed() {
            "Hide Sidebar"
        } else if self.details.shows_content() {
            "Show Sidebar"
        } else {
            "Show Package"
        };
        self.navigation_toggle.set_tooltip_text(Some(tooltip));
    }

    fn busy(&self, busy: bool, label: &str) {
        self.busy.set(busy);
        self.open.set_enabled(!busy);
        self.welcome_open.set_sensitive(!busy);
        self.extract
            .set_sensitive(!busy && self.path.borrow().is_some());
        self.convert
            .set_enabled(!busy && self.path.borrow().is_some() && self.can_convert.get());
        self.send_ps4
            .set_enabled(!busy && self.path.borrow().is_some() && self.can_convert.get());
        self.send_batch.set_enabled(!busy);
        self.send_address.set_sensitive(!busy);
        for index in [2, 3, 4] {
            self.navigation_list
                .row_at_index(index)
                .unwrap()
                .set_sensitive(self.path.borrow().is_some());
        }
        let ps3 = self.path.borrow().is_some() && !self.can_convert.get();
        self.link_rap.set_enabled(!busy && ps3);
        self.liberate.set_enabled(!busy);
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
            .follows_content_size(false)
            .content_width(640)
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
                    *ui.details_data.borrow_mut() = Some(details.clone());
                    *ui.rap.borrow_mut() = None;
                    ui.rap_source.set_subtitle("None");
                    ui.rap_source.set_visible(!details.can_convert);
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
                    ui.navigation_list
                        .select_row(ui.navigation_list.row_at_index(0).as_ref());
                    ui.show_task(0);
                    ui.pages.set_visible_child(&ui.task_pages);
                    ui.navigation_list.set_sensitive(true);
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

    fn choose_rap(self: &Rc<Self>) {
        if self.busy.get() {
            return;
        }
        self.busy(true, "Choose a RAP file…");
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let filter = gtk::FileFilter::new();
            filter.set_name(Some("RAP license files"));
            filter.add_pattern("*.rap");
            filter.add_pattern("*.RAP");
            let filters = gio::ListStore::new::<gtk::FileFilter>();
            filters.append(&filter);
            let dialog = gtk::FileDialog::builder()
                .title("Link RAP to PS3 Package")
                .filters(&filters)
                .build();
            match dialog.open_future(ui.window.upgrade().as_ref()).await {
                Ok(file) => {
                    if let Some(path) = file.path() {
                        let input = path.clone();
                        match gio::spawn_blocking(move || {
                            package::read_rap(&input)
                                .map(|_| ())
                                .map_err(|e| e.to_string())
                        })
                        .await
                        {
                            Ok(Ok(())) => {
                                ui.rap_source.set_subtitle(&glib::markup_escape_text(
                                    &path.display().to_string(),
                                ));
                                *ui.rap.borrow_mut() = Some(path);
                            }
                            Ok(Err(e)) => ui.error("Could Not Link RAP", &e),
                            Err(_) => ui.error(
                                "Could Not Link RAP",
                                "The background worker stopped unexpectedly.",
                            ),
                        }
                    } else {
                        ui.error("Local File Required", "Choose a local RAP file.");
                    }
                }
                Err(e) if e.matches(gtk::DialogError::Dismissed) => {}
                Err(e) => ui.error("Could Not Link RAP", &e.to_string()),
            }
            ui.busy(false, "");
        });
    }

    fn choose_liberation(self: &Rc<Self>) {
        if self.busy.get() {
            return;
        }
        self.busy(true, "Choose liberation source…");
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let dialog = adw::AlertDialog::builder()
                .follows_content_size(false)
                .content_width(640)
                .heading("Liberate")
                .body("Choose a PS3 PKG or an extracted game folder. Then save liberated files as a new folder or PKG.")
                .build();
            dialog.add_response("cancel", "Cancel");
            dialog.add_response("folder", "Extracted Folder…");
            dialog.add_response("pkg", "Choose PKG…");
            if ui.path.borrow().is_some() && !ui.can_convert.get() {
                dialog.add_response("loaded", "Use Loaded PKG");
            }
            dialog.set_close_response("cancel");
            let choice = dialog.choose_future(ui.window.upgrade().as_ref()).await;
            let source = match choice.as_str() {
                "loaded" => ui.path.borrow().clone().unwrap(),
                "pkg" | "folder" => {
                    let picker = gtk::FileDialog::builder()
                        .title("Liberate — Choose Source")
                        .build();
                    let selection = if choice == "folder" {
                        picker
                            .select_folder_future(ui.window.upgrade().as_ref())
                            .await
                    } else {
                        let filter = gtk::FileFilter::new();
                        filter.set_name(Some("PS3 packages"));
                        filter.add_pattern("*.pkg");
                        filter.add_pattern("*.PKG");
                        let filters = gio::ListStore::new::<gtk::FileFilter>();
                        filters.append(&filter);
                        picker.set_filters(Some(&filters));
                        picker.open_future(ui.window.upgrade().as_ref()).await
                    };
                    match selection {
                        Ok(file) => match file.path() {
                            Some(path) => path,
                            None => {
                                ui.busy(false, "");
                                ui.error("Local Source Required", "Choose a local PKG or folder.");
                                return;
                            }
                        },
                        Err(e) => {
                            ui.busy(false, "");
                            if !e.matches(gtk::DialogError::Dismissed) {
                                ui.error("Could Not Choose Source", &e.to_string());
                            }
                            return;
                        }
                    }
                }
                _ => {
                    ui.busy(false, "");
                    return;
                }
            };
            let input = source.clone();
            let result = gio::spawn_blocking(move || {
                let id = package::liberation_content_id(&input)?;
                let rap = package::find_rap(&input, &id);
                Ok::<_, String>((id, rap))
            })
            .await;
            let (id, detected) = match result {
                Ok(Ok(value)) => value,
                other => {
                    ui.busy(false, "");
                    let error = match other {
                        Ok(Err(e)) => e,
                        _ => "The background worker stopped unexpectedly.".into(),
                    };
                    ui.error("Could Not Read Source", &error);
                    return;
                }
            };
            let linked = if ui.path.borrow().as_ref() == Some(&source) {
                ui.rap.borrow().clone()
            } else {
                None
            };
            let note = detected.as_ref().err().cloned().unwrap_or_default();
            let mut rap = linked.or_else(|| detected.ok().flatten());
            let dialog = adw::AlertDialog::builder().heading("Liberate — Link RAP")
                .follows_content_size(false)
                .content_width(640)
                .body(format!("{}\n\nContent ID: {id}\n\n{}\n{note}", source.display(),
                    rap.as_ref().map(|p| format!("RAP: {}", p.display())).unwrap_or_else(||
                        "No matching RAP found beside the source or in its exdata folder. Link a RAP to continue.".into())))
                .build();
            dialog.add_response("cancel", "Cancel");
            dialog.add_response("link", "Link RAP…");
            dialog.add_response("continue", "Continue");
            dialog.set_response_enabled("continue", rap.is_some());
            dialog.set_response_appearance("continue", adw::ResponseAppearance::Suggested);
            dialog.set_default_response(Some(if rap.is_some() { "continue" } else { "link" }));
            dialog.set_close_response("cancel");
            match dialog
                .choose_future(ui.window.upgrade().as_ref())
                .await
                .as_str()
            {
                "continue" => {}
                "link" => {
                    let filter = gtk::FileFilter::new();
                    filter.set_name(Some("RAP license files"));
                    filter.add_pattern("*.rap");
                    filter.add_pattern("*.RAP");
                    let filters = gio::ListStore::new::<gtk::FileFilter>();
                    filters.append(&filter);
                    let picker = gtk::FileDialog::builder()
                        .title("Link RAP")
                        .filters(&filters)
                        .build();
                    match picker.open_future(ui.window.upgrade().as_ref()).await {
                        Ok(file) => rap = file.path(),
                        Err(e) => {
                            ui.busy(false, "");
                            if !e.matches(gtk::DialogError::Dismissed) {
                                ui.error("Could Not Link RAP", &e.to_string());
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
            ui.busy(false, "");
            if rap.is_none() {
                ui.error("Local File Required", "Choose a local RAP file.");
                return;
            }
            ui.destination_from(Operation::Liberate, source, rap);
        });
    }

    fn choose_destination(self: &Rc<Self>, operation: Operation) {
        if self.busy.get() {
            return;
        }
        let Some(source) = self.path.borrow().clone() else {
            return;
        };
        let rap = self.rap.borrow().clone();
        self.destination_from(operation, source, rap);
    }

    fn destination_from(
        self: &Rc<Self>,
        operation: Operation,
        source: PathBuf,
        rap: Option<PathBuf>,
    ) {
        let converting = operation == Operation::Convert;
        let liberating = operation == Operation::Liberate;
        if self.busy.get() {
            return;
        }
        if liberating && rap.is_none() {
            return;
        }
        self.busy(true, "Choose a destination…");
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let directory = if liberating {
                let dialog = adw::AlertDialog::builder()
                    .follows_content_size(false)
                    .content_width(640)
                    .heading("Liberate — Output")
                    .body("Save liberated files directly into a new folder, or repack them into a PKG. Folder output creates a new -liberated folder inside your chosen destination.")
                    .build();
                dialog.add_response("cancel", "Cancel");
                dialog.add_response("pkg", "PKG…");
                dialog.add_response("folder", "Folder…");
                dialog.set_response_appearance("folder", adw::ResponseAppearance::Suggested);
                dialog.set_default_response(Some("folder"));
                dialog.set_close_response("cancel");
                match dialog
                    .choose_future(ui.window.upgrade().as_ref())
                    .await
                    .as_str()
                {
                    "folder" => true,
                    "pkg" => false,
                    _ => {
                        ui.busy(false, "");
                        return;
                    }
                }
            } else {
                false
            };
            let saving_file = converting || (liberating && !directory);
            let mut update = None;
            if converting {
                let dialog = adw::AlertDialog::builder()
                    .follows_content_size(false)
                    .content_width(640)
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
                } else if directory {
                    "Choose Liberation Parent Folder"
                } else if liberating {
                    "Save Liberated PKG"
                } else {
                    "Choose Extraction Parent Folder"
                })
                .accept_label(if converting {
                    "Convert"
                } else if liberating {
                    "Liberate"
                } else {
                    "Extract Here"
                })
                .build();
            let selection = if saving_file {
                let name = if liberating {
                    format!(
                        "{}-liberated.pkg",
                        (if source.is_dir() {
                            source.file_name()
                        } else {
                            source.file_stem()
                        })
                        .unwrap_or_default()
                        .to_string_lossy()
                    )
                } else {
                    source
                        .with_extension("zar")
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned()
                };
                dialog.set_initial_name(Some(&name));
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
            let destination = if saving_file {
                parent
            } else if directory {
                package::destination(&source, &parent, "-liberated")
            } else {
                package::destination(&source, &parent, "-extracted")
            };
            ui.busy(
                true,
                if liberating {
                    "Liberating…"
                } else if saving_file {
                    "Converting package…"
                } else {
                    "Extracting package…"
                },
            );
            ui.extraction_dialog.set_title(if converting {
                "Converting to ZAR"
            } else if liberating {
                "Liberating"
            } else {
                "Extracting Package"
            });
            ui.show_extraction();
            let cancellation = ui.cancellation.clone();
            let progress = Arc::new(Mutex::new(None::<(u64, u64)>));
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
                } else if liberating {
                    package::liberate(&source, rap.as_ref().unwrap(), &output, directory, &cancellation, progress).map_err(|e| {
                        if matches!(e.downcast_ref::<ps3_pkg::Error>(), Some(ps3_pkg::Error::IncompleteExtraction { .. })) {
                            format!("{e}\n\nRemove the incomplete output folder before retrying. Existing files were not replaced.")
                        } else { e.to_string() }
                    })
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
                        .follows_content_size(false)
                        .content_width(640)
                        .heading(if liberating {
                            "Liberation Complete"
                        } else if saving_file {
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
                        let folder = if saving_file {
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
                    if liberating {
                        "Liberation Stopped"
                    } else if saving_file {
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

    fn choose_ps4(self: &Rc<Self>, batch: bool) {
        if self.busy.get() || (!batch && !self.can_convert.get()) {
            return;
        }
        let ps4 = match self.send_address.text().parse::<std::net::Ipv4Addr>() {
            Ok(ip) if !ip.is_unspecified() && !ip.is_multicast() => ip,
            _ => {
                self.error(
                    "Invalid PS4 Address",
                    "Enter a valid IPv4 address, for example 192.168.1.100.",
                );
                return;
            }
        };
        self.busy(true, "Preparing PS4 transfer…");
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let paths = if batch {
                let filter = gtk::FileFilter::new();
                filter.set_name(Some("PS4 packages"));
                filter.add_pattern("*.pkg");
                filter.add_pattern("*.PKG");
                let filters = gio::ListStore::new::<gtk::FileFilter>();
                filters.append(&filter);
                let dialog = gtk::FileDialog::builder()
                    .title("Send PS4 Packages")
                    .filters(&filters)
                    .build();
                let result = dialog
                    .open_multiple_future(ui.window.upgrade().as_ref())
                    .await;
                let files = match result {
                    Ok(files) => files,
                    Err(e) => {
                        ui.busy(false, "");
                        if !e.matches(gtk::DialogError::Dismissed) {
                            ui.error("Could Not Select Packages", &e.to_string());
                        }
                        return;
                    }
                };
                let paths = files
                    .iter::<gio::File>()
                    .map(|file| file.ok().and_then(|file| file.path()))
                    .collect::<Option<Vec<_>>>();
                match paths {
                    Some(paths) if !paths.is_empty() => paths,
                    _ => {
                        ui.busy(false, "");
                        ui.error(
                            "Local Files Required",
                            "Choose at least one local PS4 package.",
                        );
                        return;
                    }
                }
            } else {
                ui.path.borrow().clone().into_iter().collect()
            };
            let count = paths.len();
            ui.busy(true, "Sending to PS4…");
            ui.extraction_dialog.set_title("Sending to PS4");
            ui.show_extraction();
            ui.extraction_status
                .set_label("Checking selected packages…");
            ui.extraction_transfer.set_label("Waiting for PS4…");
            let cancellation = ui.cancellation.clone();
            let progress = Arc::new(Mutex::new(None::<(usize, u64, u64)>));
            let worker_progress = progress.clone();
            let mut last_sample = Instant::now();
            let mut last_written = 0;
            let mut last_index = 0;
            let timer = glib::timeout_add_local(
                Duration::from_millis(250),
                glib::clone!(
                    #[weak]
                    ui,
                    #[upgrade_or]
                    glib::ControlFlow::Break,
                    move || {
                        if let Some((index, written, total)) = *progress.lock().unwrap() {
                            let now = Instant::now();
                            let rate = written.saturating_sub(if index == last_index {
                                last_written
                            } else {
                                0
                            }) as f64
                                / now.duration_since(last_sample).as_secs_f64();
                            ui.update_progress(written, total, rate);
                            if !ui.cancellation.load(Ordering::Relaxed) {
                                ui.extraction_status.set_label(&format!(
                                    "Package {} of {count} · {}",
                                    index + 1,
                                    if written == total {
                                        "Finishing transfer…"
                                    } else if written == 0 {
                                        "Waiting for PS4…"
                                    } else {
                                        "Sending package…"
                                    }
                                ));
                            }
                            last_index = index;
                            last_written = written;
                            last_sample = now;
                        } else {
                            ui.extraction_progress.pulse();
                        }
                        glib::ControlFlow::Continue
                    }
                ),
            );
            let result = gio::spawn_blocking(move || {
                let details = paths
                    .iter()
                    .map(|path| {
                        if cancellation.load(Ordering::Relaxed) {
                            return Err("Sending cancelled".to_owned());
                        }
                        let details = package::inspect(path)
                            .map_err(|e| format!("{}: {e}", path.display()))?;
                        if !details.can_convert {
                            return Err(format!(
                                "{} is not a PS4 package. No packages were sent.",
                                path.display()
                            ));
                        }
                        Ok(details)
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let packages = paths
                    .iter()
                    .zip(&details)
                    .map(|(path, details)| {
                        (
                            path.as_path(),
                            ps4_send::PackageInfo {
                                name: &details.title,
                                content_id: &details.content_id,
                                category: &details.category,
                                size: details.size,
                                icon: details.icon.as_deref(),
                            },
                        )
                    })
                    .collect::<Vec<_>>();
                ps4_send::send_batch(&packages, ps4, cancellation, |index, written, total| {
                    *worker_progress.lock().unwrap() = Some((index, written, total))
                })
            })
            .await;
            timer.remove();
            ui.extraction_dialog.force_close();
            ui.busy(false, "");
            match result {
                Ok(Ok(())) => ui.toasts.add_toast(adw::Toast::new(&format!(
                    "{count} package(s) transferred. Check installation status on PS4."
                ))),
                Ok(Err(e)) => ui.error("Could Not Send Package", &e),
                Err(_) => ui.error(
                    "Could Not Send Package",
                    "The transfer worker stopped unexpectedly.",
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
        open: gio::SimpleAction::new("open", None),
        welcome_open: builder.object("welcome_open").unwrap(),
        welcome: builder.object("welcome").unwrap(),
        extract: builder.object("extract").unwrap(),
        convert: gio::SimpleAction::new("convert", None),
        send_ps4: gio::SimpleAction::new("send-ps4", None),
        send_batch: gio::SimpleAction::new("send-batch", None),
        link_rap: gio::SimpleAction::new("link-rap", None),
        liberate: gio::SimpleAction::new("liberate", None),
        rap_source: builder.object("rap_source").unwrap(),
        rap: RefCell::new(None),
        pages: builder.object("pages").unwrap(),
        details: builder.object("details").unwrap(),
        navigation_list: builder.object("navigation_list").unwrap(),
        navigation_toggle: builder.object("navigation_toggle").unwrap(),
        task_pages: builder.object("task_pages").unwrap(),
        summary_page: builder.object("summary_page").unwrap(),
        send_page: builder.object("send_page").unwrap(),
        send_address: builder.object("send_address").unwrap(),
        extract_page: builder.object("extract_page").unwrap(),
        convert_page: builder.object("convert_page").unwrap(),
        info_page: builder.object("info_page").unwrap(),
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
        details_data: RefCell::new(None),
    });
    ui.welcome_open.connect_clicked(glib::clone!(
        #[weak]
        ui,
        move |_| ui.choose_package()
    ));
    ui.navigation_list.select_row(Some(
        &builder.object::<gtk::ListBoxRow>("summary_nav").unwrap(),
    ));
    ui.navigation_list.connect_row_selected(glib::clone!(
        #[weak]
        ui,
        move |_, row| {
            if let Some(row) = row {
                ui.show_task(row.index());
            }
        }
    ));
    ui.navigation_list.connect_row_activated(glib::clone!(
        #[weak]
        ui,
        move |_, row| ui.show_task(row.index())
    ));
    ui.navigation_toggle.connect_clicked(glib::clone!(
        #[weak]
        ui,
        move |_| ui.toggle_sidebar()
    ));
    ui.details.connect_collapsed_notify(glib::clone!(
        #[weak]
        ui,
        move |_| ui.update_sidebar_toggle()
    ));
    ui.details.connect_show_content_notify(glib::clone!(
        #[weak]
        ui,
        move |_| ui.update_sidebar_toggle()
    ));
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
        move |_| ui.choose_destination(Operation::Extract)
    ));
    ui.convert.set_enabled(false);
    ui.convert.connect_activate(glib::clone!(
        #[weak]
        ui,
        move |_, _| ui.choose_destination(Operation::Convert)
    ));
    window.add_action(&ui.convert);
    ui.send_ps4.set_enabled(false);
    ui.send_ps4.connect_activate(glib::clone!(
        #[weak]
        ui,
        move |_, _| ui.choose_ps4(false)
    ));
    window.add_action(&ui.send_ps4);
    ui.send_batch.connect_activate(glib::clone!(
        #[weak]
        ui,
        move |_, _| ui.choose_ps4(true)
    ));
    window.add_action(&ui.send_batch);
    ui.send_address.connect_activate(glib::clone!(
        #[weak]
        ui,
        move |_| ui.choose_ps4(!ui.can_convert.get())
    ));
    ui.link_rap.set_enabled(false);
    ui.link_rap.connect_activate(glib::clone!(
        #[weak]
        ui,
        move |_, _| ui.choose_rap()
    ));
    window.add_action(&ui.link_rap);
    ui.liberate.set_enabled(true);
    ui.liberate.connect_activate(glib::clone!(
        #[weak]
        ui,
        move |_, _| ui.choose_liberation()
    ));
    window.add_action(&ui.liberate);
    let about = gio::SimpleAction::new("about", None);
    about.connect_activate(glib::clone!(
        #[weak]
        window,
        move |_, _| {
            adw::AboutDialog::builder()
                .follows_content_size(false)
                .content_width(640)
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
    ui.open.connect_activate(glib::clone!(
        #[weak]
        ui,
        move |_, _| ui.choose_package()
    ));
    window.add_action(&ui.open);
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
    ui.busy(false, "");
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
        assert!(ui.details.is_ancestor(&ui.toasts));
        let sidebar_icon = ui.navigation_toggle.icon_name();
        ui.details.set_collapsed(true);
        ui.details.set_show_content(false);
        assert_eq!(ui.navigation_toggle.icon_name(), sidebar_icon);
        ui.details.set_show_content(true);
        ui.details.set_collapsed(false);
        assert_eq!(ui.navigation_toggle.icon_name(), sidebar_icon);
        assert!(!ui.extract.is_sensitive());
        assert!(!ui.convert.is_enabled());
        assert!(!ui.send_ps4.is_enabled());
        assert!(ui.send_batch.is_enabled());
        assert!(ui.send_address.is_sensitive());
        ui.navigation_list
            .select_row(ui.navigation_list.row_at_index(1).as_ref());
        assert_eq!(
            ui.pages.visible_child(),
            Some(ui.task_pages.clone().upcast())
        );
        assert_eq!(
            ui.task_pages.visible_child(),
            Some(ui.send_page.clone().upcast())
        );
        ui.busy(true, "Sending…");
        assert!(!ui.send_batch.is_enabled());
        assert!(!ui.send_address.is_sensitive());
        ui.busy(false, "");
        ui.navigation_list
            .select_row(ui.navigation_list.row_at_index(0).as_ref());
        assert_eq!(ui.pages.visible_child(), Some(ui.welcome.clone().upcast()));
        assert!(!ui.link_rap.is_enabled());
        assert!(ui.liberate.is_enabled());
        assert_eq!(
            ui.task_pages.visible_child(),
            Some(ui.summary_page.clone().upcast())
        );
        ui.liberate.activate(None);
        let context = glib::MainContext::default();
        while ui.window.upgrade().unwrap().visible_dialog().is_none() {
            context.iteration(true);
        }
        let dialog = ui
            .window
            .upgrade()
            .unwrap()
            .visible_dialog()
            .unwrap()
            .downcast::<adw::AlertDialog>()
            .unwrap();
        assert_eq!(dialog.heading().as_deref(), Some("Liberate"));
        assert!(dialog.has_response("pkg"));
        assert!(dialog.has_response("folder"));
        assert!(!dialog.has_response("loaded"));
        assert!(dialog.close());
        while ui.busy.get() {
            context.iteration(true);
        }
        assert!(ui.liberate.is_enabled());
        ui.destination_from(
            Operation::Liberate,
            PathBuf::from("game.pkg"),
            Some(PathBuf::from("license.rap")),
        );
        while ui.window.upgrade().unwrap().visible_dialog().is_none() {
            context.iteration(true);
        }
        let dialog = ui
            .window
            .upgrade()
            .unwrap()
            .visible_dialog()
            .unwrap()
            .downcast::<adw::AlertDialog>()
            .unwrap();
        assert_eq!(dialog.heading().as_deref(), Some("Liberate — Output"));
        assert!(dialog.has_response("pkg"));
        assert!(dialog.has_response("folder"));
        assert_eq!(dialog.default_response().as_deref(), Some("folder"));
        assert!(dialog.close());
        while ui.busy.get() {
            context.iteration(true);
        }
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
        assert_eq!(ui.send_ps4.is_enabled(), expected.can_convert);
        assert!(ui.send_batch.is_enabled());
        assert!(ui.send_address.is_sensitive());
        assert_eq!(ui.link_rap.is_enabled(), !expected.can_convert);
        assert_eq!(ui.rap_source.is_visible(), !expected.can_convert);
        assert!(ui.liberate.is_enabled());
        if !expected.can_convert {
            *ui.rap.borrow_mut() = Some(PathBuf::from("test.rap"));
            ui.busy(false, "");
            assert!(ui.liberate.is_enabled());
            ui.busy(true, "Converting…");
            assert!(!ui.liberate.is_enabled());
            assert!(!ui.link_rap.is_enabled());
            ui.busy(false, "");
            ui.load(file.clone());
            while ui.busy.get() {
                context.iteration(true);
            }
            assert!(ui.rap.borrow().is_none());
            assert!(ui.liberate.is_enabled());
            ui.liberate.activate(None);
            context.block_on(glib::timeout_future(Duration::from_millis(100)));
            let source_dialog = ui
                .window
                .upgrade()
                .unwrap()
                .visible_dialog()
                .unwrap()
                .downcast::<adw::AlertDialog>()
                .unwrap();
            source_dialog.emit_by_name::<()>("response", &[&"loaded"]);
            source_dialog.force_close();
            context.block_on(glib::timeout_future(Duration::from_millis(500)));
            let rap_dialog = ui
                .window
                .upgrade()
                .unwrap()
                .visible_dialog()
                .unwrap()
                .downcast::<adw::AlertDialog>()
                .unwrap();
            assert_eq!(rap_dialog.heading().as_deref(), Some("Liberate — Link RAP"));
            let width = rap_dialog.child().unwrap().width();
            assert!(
                width >= 600,
                "Link RAP rendered width: {width}, expected at least 600"
            );
            rap_dialog.close();
            while ui.busy.get() {
                context.iteration(true);
            }
        }
        assert!(!ui.title.text().is_empty());
        assert_eq!(
            ui.pages.visible_child(),
            Some(ui.task_pages.clone().upcast())
        );
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
        ui.navigation_list
            .select_row(ui.navigation_list.row_at_index(4).as_ref());
        assert_eq!(
            ui.task_pages.visible_child(),
            Some(ui.info_page.clone().upcast())
        );
        assert!(ui.metadata.buffer().char_count() > 0);
        assert_eq!(
            ui.pages.visible_child(),
            Some(ui.task_pages.clone().upcast())
        );
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
