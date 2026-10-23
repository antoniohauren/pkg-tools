use adw::prelude::*;
use gtk::{gio, glib};
use std::{cell::Cell, path::PathBuf, rc::Rc};

pub struct View {
    pub widget: gtk::Stack,
    status: adw::StatusPage,
    scroll: gtk::ScrolledWindow,
    list: gtk::ListView,
    requested: Cell<bool>,
    generation: Cell<u64>,
}

struct Row {
    title: String,
    description: String,
    icon: Option<Vec<u8>>,
    heading: bool,
}

impl View {
    pub fn new() -> Rc<Self> {
        let widget = gtk::Stack::new();
        let status = adw::StatusPage::builder()
            .title("No Package Loaded")
            .description("Open a PS3 or PS4 package to view trophy definitions.")
            .icon_name("starred-symbolic")
            .build();
        let list = gtk::ListView::new(None::<gtk::NoSelection>, Some(factory()));
        let scroll = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .child(&list)
            .build();
        widget.add_child(&status);
        widget.add_child(&scroll);
        Rc::new(Self {
            widget,
            status,
            scroll,
            list,
            requested: Cell::new(false),
            generation: Cell::new(0),
        })
    }

    pub fn reset(&self) {
        self.generation.set(self.generation.get() + 1);
        self.requested.set(false);
        self.list.set_model(None::<&gtk::NoSelection>);
        self.status.set_title("No Package Loaded");
        self.status.set_description(Some(
            "Open a PS3 or PS4 package to view trophy definitions.",
        ));
        self.widget.set_visible_child(&self.status);
    }

    pub fn load(self: &Rc<Self>, path: Option<PathBuf>) {
        let Some(path) = path else {
            return;
        };
        if self.requested.replace(true) {
            return;
        }
        self.status.set_title("Loading Trophies…");
        self.status
            .set_description(Some("Reading trophy definitions without extracting files."));
        let generation = self.generation.get();
        let view = self.clone();
        glib::spawn_future_local(async move {
            let result = gio::spawn_blocking(move || {
                pkg_ops::trophies::read(&path).map_err(|e| e.to_string())
            })
            .await;
            if generation != view.generation.get() {
                return;
            }
            match result {
                Ok(Ok(sets)) if !sets.is_empty() => {
                    let store = gio::ListStore::new::<glib::BoxedAnyObject>();
                    for set in sets {
                        let count = set.trophies.len();
                        store.append(&glib::BoxedAnyObject::new(Row {
                            title: set.title,
                            description: set.error.unwrap_or_else(|| {
                                format!(
                                    "{count} trophies · {} · Definitions only, not earned status",
                                    set.path
                                )
                            }),
                            icon: None,
                            heading: true,
                        }));
                        for trophy in set.trophies {
                            store.append(&glib::BoxedAnyObject::new(Row {
                                title: format!("{:03} · {}", trophy.id, trophy.name),
                                description: format!(
                                    "{}{} · Group {}\n{}",
                                    trophy.grade,
                                    if trophy.hidden { " · Hidden" } else { "" },
                                    trophy.group,
                                    trophy.description
                                ),
                                icon: trophy.icon,
                                heading: false,
                            }));
                        }
                    }
                    view.list
                        .set_model(Some(&gtk::NoSelection::new(Some(store))));
                    view.widget.set_visible_child(&view.scroll);
                }
                result => {
                    let (title, description) = match result {
                        Ok(Ok(_)) => (
                            "No Trophy Sets",
                            "This package contains no trophy archives.".to_owned(),
                        ),
                        Ok(Err(error)) => ("Could Not Read Trophies", error),
                        Err(_) => (
                            "Could Not Read Trophies",
                            "The background worker stopped unexpectedly.".into(),
                        ),
                    };
                    view.status.set_title(title);
                    view.status.set_description(Some(&description));
                }
            }
        });
    }
}

fn factory() -> gtk::SignalListItemFactory {
    let factory = gtk::SignalListItemFactory::new();
    factory.connect_setup(|_, object| {
        let item = object.downcast_ref::<gtk::ListItem>().unwrap();
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 16);
        row.set_margin_start(24);
        row.set_margin_end(24);
        row.set_margin_top(12);
        row.set_margin_bottom(12);
        let icon = gtk::Image::builder()
            .pixel_size(56)
            .valign(gtk::Align::Start)
            .build();
        let text = gtk::Box::new(gtk::Orientation::Vertical, 6);
        text.set_hexpand(true);
        for _ in 0..2 {
            let label = gtk::Label::builder()
                .xalign(0.0)
                .wrap(true)
                .selectable(true)
                .build();
            label.set_wrap_mode(gtk::pango::WrapMode::WordChar);
            text.append(&label);
        }
        text.last_child().unwrap().add_css_class("dim-label");
        row.append(&icon);
        row.append(&text);
        item.set_child(Some(&row));
    });
    factory.connect_bind(|_, object| {
        let item = object.downcast_ref::<gtk::ListItem>().unwrap();
        let object = item
            .item()
            .unwrap()
            .downcast::<glib::BoxedAnyObject>()
            .unwrap();
        let data = object.borrow::<Row>();
        let row = item.child().unwrap();
        let icon = row.first_child().unwrap().downcast::<gtk::Image>().unwrap();
        icon.set_icon_name(Some("starred-symbolic"));
        if let Some(bytes) = data
            .icon
            .as_deref()
            .filter(|b| crate::package::valid_icon(b))
            && let Ok(texture) = gtk::gdk::Texture::from_bytes(&glib::Bytes::from(bytes))
        {
            icon.set_paintable(Some(&texture));
        }
        let text = row.last_child().unwrap();
        let title = text
            .first_child()
            .unwrap()
            .downcast::<gtk::Label>()
            .unwrap();
        title.set_label(&data.title);
        title.remove_css_class("heading");
        title.remove_css_class("title-3");
        title.add_css_class(if data.heading { "title-3" } else { "heading" });
        text.last_child()
            .unwrap()
            .downcast::<gtk::Label>()
            .unwrap()
            .set_label(&data.description);
    });
    factory
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires a graphical session"]
    fn trophy_page_loading_empty_error_and_stale_worker_states() {
        adw::init().unwrap();
        let view = View::new();
        let context = glib::MainContext::default();
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/ps3-list-explicit.pkg");
        let wait = || {
            for _ in 0..6000 {
                context.block_on(glib::timeout_future(std::time::Duration::from_millis(10)));
                if view.status.title() != "Loading Trophies…" || view.list.model().is_some() {
                    return;
                }
            }
            panic!("trophy worker timed out");
        };
        view.load(Some(fixture.clone()));
        assert_eq!(view.status.title(), "Loading Trophies…");
        wait();
        assert_eq!(view.status.title(), "No Trophy Sets");
        view.reset();
        view.load(Some(PathBuf::from("/nonexistent/trophies.pkg")));
        wait();
        assert_eq!(view.status.title(), "Could Not Read Trophies");
        view.reset();
        view.load(Some(fixture));
        view.reset();
        context.block_on(glib::timeout_future(std::time::Duration::from_millis(200)));
        assert_eq!(view.status.title(), "No Package Loaded");
        assert!(view.list.model().is_none());
        if let Some(path) = std::env::var_os("PKG_TOOLS_TROPHY_FIXTURE") {
            view.load(Some(PathBuf::from(path)));
            wait();
            let model = view.list.model().unwrap();
            assert!(model.n_items() > 1);
            assert_eq!(
                view.widget.visible_child(),
                Some(view.scroll.clone().upcast())
            );
            let object = model
                .item(1)
                .unwrap()
                .downcast::<glib::BoxedAnyObject>()
                .unwrap();
            let row = object.borrow::<Row>();
            assert!(!row.heading);
            assert!(row.description.contains("Platinum"));
            assert!(crate::package::valid_icon(row.icon.as_deref().unwrap()));
            let window = gtk::Window::builder()
                .child(&view.widget)
                .default_width(800)
                .default_height(600)
                .build();
            window.present();
            context.block_on(glib::timeout_future(std::time::Duration::from_millis(200)));
            assert!(view.list.is_mapped());
            window.close();
        }
    }
}
