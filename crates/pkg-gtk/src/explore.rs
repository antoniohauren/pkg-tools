use gtk::{gio, glib, prelude::*};
use pkg_ops::{FileEntry, FileKind};
use std::{collections::BTreeMap, rc::Rc};

// Child stores are created only when folders expand; ListView recycles row widgets.
pub fn tree(children: BTreeMap<String, Vec<FileEntry>>) -> gtk::TreeListModel {
    let children = Rc::new(children);
    let root = store(children.get("").map(Vec::as_slice).unwrap_or_default());
    gtk::TreeListModel::new(root, false, false, move |object| {
        let entry = object
            .downcast_ref::<glib::BoxedAnyObject>()?
            .borrow::<FileEntry>();
        if entry.kind != FileKind::Directory {
            return None;
        }
        Some(
            store(
                children
                    .get(&entry.path)
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
            )
            .upcast(),
        )
    })
}

pub fn index(entries: Vec<FileEntry>) -> BTreeMap<String, Vec<FileEntry>> {
    let mut children = BTreeMap::<String, Vec<FileEntry>>::new();
    for entry in entries {
        let parent = entry.path.rsplit_once('/').map_or("", |(parent, _)| parent);
        children.entry(parent.to_owned()).or_default().push(entry);
    }
    for entries in children.values_mut() {
        entries.sort_by(|a, b| {
            (a.kind != FileKind::Directory, &a.path).cmp(&(b.kind != FileKind::Directory, &b.path))
        });
    }
    children
}

fn store(entries: &[FileEntry]) -> gio::ListStore {
    let store = gio::ListStore::new::<glib::BoxedAnyObject>();
    for entry in entries {
        store.append(&glib::BoxedAnyObject::new(entry.clone()));
    }
    store
}

pub fn selected_paths(selection: &gtk::MultiSelection) -> Vec<String> {
    let selected = selection.selection();
    gtk::BitsetIter::init_first(&selected)
        .map(|(iter, first)| std::iter::once(first).chain(iter).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|index| {
            let row = selection.item(index)?.downcast::<gtk::TreeListRow>().ok()?;
            let object = row.item()?.downcast::<glib::BoxedAnyObject>().ok()?;
            Some(object.borrow::<FileEntry>().path.clone())
        })
        .collect()
}

pub fn factory() -> gtk::SignalListItemFactory {
    let factory = gtk::SignalListItemFactory::new();
    factory.connect_setup(|_, object| {
        let item = object.downcast_ref::<gtk::ListItem>().unwrap();
        let expander = gtk::TreeExpander::new();
        let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        row.set_margin_top(8);
        row.set_margin_bottom(8);
        row.set_margin_end(12);
        let name = gtk::Label::new(None);
        name.set_xalign(0.0);
        name.set_hexpand(true);
        name.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
        let size = gtk::Label::new(None);
        size.add_css_class("dim-label");
        size.add_css_class("numeric");
        row.append(&gtk::Image::new());
        row.append(&name);
        row.append(&size);
        expander.set_child(Some(&row));
        item.set_child(Some(&expander));
    });
    factory.connect_bind(|_, object| {
        let item = object.downcast_ref::<gtk::ListItem>().unwrap();
        let row = item.item().unwrap().downcast::<gtk::TreeListRow>().unwrap();
        let object = row
            .item()
            .unwrap()
            .downcast::<glib::BoxedAnyObject>()
            .unwrap();
        let entry = object.borrow::<FileEntry>();
        let expander = item
            .child()
            .unwrap()
            .downcast::<gtk::TreeExpander>()
            .unwrap();
        expander.set_list_row(Some(&row));
        expander.set_tooltip_text(Some(&entry.path));
        let content = expander.child().unwrap();
        let icon = content
            .first_child()
            .unwrap()
            .downcast::<gtk::Image>()
            .unwrap();
        icon.set_icon_name(Some(if entry.kind == FileKind::Directory {
            "folder-symbolic"
        } else {
            "text-x-generic-symbolic"
        }));
        let name = icon
            .next_sibling()
            .unwrap()
            .downcast::<gtk::Label>()
            .unwrap();
        name.set_label(entry.path.rsplit('/').next().unwrap());
        let size = content
            .last_child()
            .unwrap()
            .downcast::<gtk::Label>()
            .unwrap();
        size.set_label(&if entry.kind == FileKind::Directory {
            "Folder".into()
        } else {
            glib::format_size(entry.size).to_string()
        });
    });
    factory.connect_unbind(|_, object| {
        let item = object.downcast_ref::<gtk::ListItem>().unwrap();
        let expander = item
            .child()
            .unwrap()
            .downcast::<gtk::TreeExpander>()
            .unwrap();
        expander.set_list_row(None::<&gtk::TreeListRow>);
    });
    factory
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps3_and_ps4_tree_preserves_paths_sizes_and_empty_folders() {
        for fixture in [
            "ps3-list-explicit.pkg",
            "ps3-list-implied.pkg",
            "ps4-selection.pkg",
        ] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures")
                .join(fixture);
            let entries = pkg_ops::list(&path).unwrap();
            let count = entries.len();
            let children = index(entries);
            assert_eq!(children.values().map(Vec::len).sum::<usize>(), count);
            assert!(
                children[""]
                    .iter()
                    .any(|entry| entry.path == "empty" && entry.kind == FileKind::Directory)
            );
            assert!(!children.contains_key("empty"));
            assert!(
                children["data/nested"]
                    .iter()
                    .any(|entry| entry.path == "data/nested/two.bin" && entry.size == 4)
            );
            for (parent, entries) in &children {
                for entry in entries {
                    assert_eq!(
                        entry.path.rsplit_once('/').map_or("", |(parent, _)| parent),
                        parent
                    );
                }
                assert!(entries.windows(2).all(|pair| (
                    pair[0].kind != FileKind::Directory,
                    &pair[0].path
                ) <= (
                    pair[1].kind != FileKind::Directory,
                    &pair[1].path
                )));
            }
        }
    }
}
