//! The app icon in the sizes the packages need, rendered from `assets/icon/crewcraft.svg` at build time.

use resvg::tiny_skia::{Pixmap, Transform};
use resvg::usvg::{Options, Tree};

use crate::{Error, Result};

/// The hicolor theme sizes installed by the Linux packages (the SVG goes in `scalable` as well).
pub const HICOLOR_SIZES: [u32; 8] = [16, 24, 32, 48, 64, 128, 256, 512];
/// The sizes inside the Windows `.ico`: small icons, the Start menu, Explorer views and the 256 px tile.
pub const ICO_SIZES: [u32; 6] = [16, 24, 32, 48, 64, 256];

/// Renders the SVG as a square PNG of `size` pixels.
pub fn render_png(svg: &[u8], size: u32) -> Result<Vec<u8>> {
    let tree = Tree::from_data(svg, &Options::default()).map_err(|error| Error::new(format!("reading the icon SVG: {error}")))?;
    let mut pixmap = Pixmap::new(size, size).ok_or_else(|| Error::new(format!("icon size {size} is not valid")))?;
    let view = tree.size();
    let scale_x = size as f32 / view.width();
    let scale_y = size as f32 / view.height();
    resvg::render(&tree, Transform::from_scale(scale_x, scale_y), &mut pixmap.as_mut());
    pixmap.encode_png().map_err(|error| Error::new(format!("encoding the {size} px icon: {error}")))
}

/// Renders every size in `sizes`, as `(size, png)` pairs.
pub fn render_sizes(svg: &[u8], sizes: &[u32]) -> Result<Vec<(u32, Vec<u8>)>> {
    sizes.iter().map(|&size| Ok((size, render_png(svg, size)?))).collect()
}

/// A Windows `.ico` holding the given PNG images (Windows reads PNG entries in icons since Vista). Sizes must be
/// 1 to 256 pixels.
pub fn ico(images: &[(u32, Vec<u8>)]) -> Result<Vec<u8>> {
    let count = u16::try_from(images.len()).map_err(|_| Error::new("too many icon images"))?;
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    let mut offset = 6 + 16 * images.len();
    for (size, png) in images {
        if *size == 0 || *size > 256 {
            return Err(Error::new(format!("an .ico image cannot be {size} px")));
        }
        // A width or height of 256 is written as 0.
        let side = (*size % 256) as u8;
        out.extend_from_slice(&[side, side, 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        let len = u32::try_from(png.len()).map_err(|_| Error::new("icon image too large"))?;
        let at = u32::try_from(offset).map_err(|_| Error::new("icon too large"))?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&at.to_le_bytes());
        offset += png.len();
    }
    for (_, png) in images {
        out.extend_from_slice(png);
    }
    Ok(out)
}
