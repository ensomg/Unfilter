//! Opening animation: easing math and the per-frame timeline.
//!
//! Pure functions only (no slint types) so the whole timeline is unit-tested.
//! `main.rs` drives [`frame`] from a 16 ms `slint::Timer` and stops the timer
//! once [`Frame::done`] is set, so nothing ticks after the splash.
//!
//! The software renderer cannot blur, rotate, round-clip or draw gradient
//! borders, so the glass is assembled from what it can draw well:
//! anti-aliased rounded rectangles, filled/stroked `Path`s and a radial
//! gradient (shadow). The rim highlight and the light band are therefore
//! generated here as path data that hugs the rounded tile.

use std::f32::consts::{PI, SQRT_2, TAU};

/// Window size (logical px); the window is fixed at 520 x 620 (ADR 004).
pub const WIN_W: f32 = 520.0;
/// Window height.
pub const WIN_H: f32 = 620.0;
/// Where the tile lands.
pub const CENTER: (f32, f32) = (WIN_W / 2.0, 292.0);
/// Final tile edge length.
pub const TILE: f32 = 128.0;
/// Logo size relative to the final tile at the end of the glide.
pub const LOGO_FRAC: f32 = 0.62;
/// Rail logo box (x, y, size) in `ui/app.slint`; the logo settles there.
pub const HEADER_LOGO: (f32, f32, f32) = (20.0, 18.0, 24.0);
/// Spring period of the droplet.
pub const SPRING_PERIOD: f32 = 0.42;
/// Total length; after this the splash is removed.
pub const TOTAL: f32 = 3.05;

/// Critically damped spring step response `1 - e^{-wt}(1 + wt)`, `w = 2π/period`.
/// Rises monotonically from 0 to 1 without overshoot.
pub fn spring(t: f32, period: f32) -> f32 {
    if t <= 0.0 {
        return 0.0;
    }
    let wt = TAU / period * t;
    1.0 - (-wt).exp() * (1.0 + wt)
}

/// Hermite smoothstep of `x` between `e0` and `e1` (clamped).
pub fn smoothstep(e0: f32, e1: f32, x: f32) -> f32 {
    let t = ((x - e0) / (e1 - e0)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

/// Perlin smootherstep (zero 1st and 2nd derivative at both ends).
pub fn smootherstep(e0: f32, e1: f32, x: f32) -> f32 {
    let t = ((x - e0) / (e1 - e0)).clamp(0.0, 1.0);
    t * t * t * (t * (t * 6.0 - 15.0) + 10.0)
}

/// Linear interpolation.
pub fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}

/// Point at perimeter fraction `s` (wraps) of a `w` x `h` rounded rectangle
/// with corner radius `r` and origin (0, 0). `s = 0` is the start of the top
/// edge; travel is clockwise on screen.
pub fn rounded_rect_point(w: f32, h: f32, r: f32, s: f32) -> (f32, f32) {
    let r = r.clamp(0.0, w.min(h) / 2.0);
    let (ew, eh) = (w - 2.0 * r, h - 2.0 * r);
    let quarter = PI * r / 2.0;
    let total = 2.0 * (ew + eh) + 4.0 * quarter;
    if total <= 0.0 {
        return (0.0, 0.0);
    }
    let mut d = s.rem_euclid(1.0) * total;
    let arc = |cx: f32, cy: f32, a0: f32, d: f32| {
        let a = a0 + if r > 0.0 { d / r } else { 0.0 };
        (cx + r * a.cos(), cy + r * a.sin())
    };
    // (length, point-at-distance) for each of the eight segments
    if d <= ew {
        return (r + d, 0.0);
    }
    d -= ew;
    if d <= quarter {
        return arc(w - r, r, -PI / 2.0, d);
    }
    d -= quarter;
    if d <= eh {
        return (w, r + d);
    }
    d -= eh;
    if d <= quarter {
        return arc(w - r, h - r, 0.0, d);
    }
    d -= quarter;
    if d <= ew {
        return (w - r - d, h);
    }
    d -= ew;
    if d <= quarter {
        return arc(r, h - r, PI / 2.0, d);
    }
    d -= quarter;
    if d <= eh {
        return (0.0, h - r - d);
    }
    d -= eh;
    arc(r, r, PI, d.min(quarter))
}

/// Convex polygon approximating the rounded rectangle (clockwise on screen).
pub fn rounded_rect_polygon(w: f32, h: f32, r: f32, n: usize) -> Vec<(f32, f32)> {
    (0..n)
        .map(|i| rounded_rect_point(w, h, r, i as f32 / n as f32))
        .collect()
}

fn fmt_points(pts: &[(f32, f32)], close: bool) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(pts.len() * 16);
    for (i, (x, y)) in pts.iter().enumerate() {
        let _ = write!(s, "{}{x:.2} {y:.2} ", if i == 0 { "M" } else { "L" });
    }
    if close && !pts.is_empty() {
        s.push('Z');
    }
    if s.is_empty() {
        // A lone move-to draws nothing but is still valid path data.
        s.push_str("M0 0");
    }
    s
}

/// Open polyline along the tile edge from perimeter fraction `start` over `len`
/// (both wrap), inset by `inset` so a stroke of width `2 * inset` hugs the edge.
pub fn rim_arc_path(size: f32, radius: f32, inset: f32, start: f32, len: f32) -> String {
    const SAMPLES: usize = 28;
    let inner = (size - 2.0 * inset).max(0.0);
    let r = (radius - inset).max(0.0);
    let pts: Vec<(f32, f32)> = (0..=SAMPLES)
        .map(|i| {
            let (x, y) =
                rounded_rect_point(inner, inner, r, start + len * i as f32 / SAMPLES as f32);
            (x + inset, y + inset)
        })
        .collect();
    fmt_points(&pts, false)
}

/// Sutherland–Hodgman: clips `subject` against the convex polygon `clip`
/// (clockwise on screen, i.e. positive signed area with y pointing down).
pub fn clip_convex(subject: &[(f32, f32)], clip: &[(f32, f32)]) -> Vec<(f32, f32)> {
    let cross = |a: (f32, f32), b: (f32, f32), p: (f32, f32)| {
        (b.0 - a.0) * (p.1 - a.1) - (b.1 - a.1) * (p.0 - a.0)
    };
    let mut out = subject.to_vec();
    for i in 0..clip.len() {
        if out.is_empty() {
            break;
        }
        let (a, b) = (clip[i], clip[(i + 1) % clip.len()]);
        let input = std::mem::take(&mut out);
        for j in 0..input.len() {
            let (p, q) = (input[j], input[(j + 1) % input.len()]);
            let (cp, cq) = (cross(a, b, p), cross(a, b, q));
            if cp >= 0.0 {
                out.push(p);
            }
            if (cp >= 0.0) != (cq >= 0.0) {
                let t = cp / (cp - cq);
                out.push((p.0 + (q.0 - p.0) * t, p.1 + (q.1 - p.1) * t));
            }
        }
    }
    out
}

/// Diagonal (45°, top-left → bottom-right travel) band of light across a
/// `size` tile with corner `radius`. `center` is the band position as a
/// fraction of the tile diagonal (0 = top-left corner, 1 = bottom-right);
/// `half_width` is in px. The band is clipped to the rounded tile.
pub fn band_path(size: f32, radius: f32, center: f32, half_width: f32) -> String {
    let c = center * size * SQRT_2;
    let (m1, m2) = ((c - half_width) * SQRT_2, (c + half_width) * SQRT_2);
    let l = size * 4.0;
    let strip = [(m1 + l, -l), (m2 + l, -l), (-l, m2 + l), (-l, m1 + l)];
    let tile = rounded_rect_polygon(size, size, radius, 48);
    let poly = clip_convex(&strip, &tile);
    if poly.len() < 3 {
        return fmt_points(&[], true);
    }
    fmt_points(&poly, true)
}

/// Everything the splash layer in `ui/app.slint` needs for one frame.
/// Positions are absolute logical px; alphas are 0..=1.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    /// Glass tile top-left x.
    pub glass_x: f32,
    /// Glass tile top-left y.
    pub glass_y: f32,
    /// Glass tile edge length.
    pub glass_size: f32,
    /// Corner radius (size/2 = circle → ~0.235·size = squircle tile).
    pub glass_radius: f32,
    /// Overall glass opacity.
    pub glass_alpha: f32,
    /// Ripple ring top-left x.
    pub ripple_x: f32,
    /// Ripple ring top-left y.
    pub ripple_y: f32,
    /// Ripple ring diameter.
    pub ripple_size: f32,
    /// Ripple ring opacity.
    pub ripple_alpha: f32,
    /// Shadow blob top-left x.
    pub shadow_x: f32,
    /// Shadow blob top-left y.
    pub shadow_y: f32,
    /// Shadow blob edge length.
    pub shadow_size: f32,
    /// Shadow opacity.
    pub shadow_alpha: f32,
    /// Clip rectangle for the logo behind the glass.
    pub clip_x: f32,
    /// Clip y.
    pub clip_y: f32,
    /// Clip width.
    pub clip_w: f32,
    /// Clip height.
    pub clip_h: f32,
    /// Logo top-left x.
    pub logo_x: f32,
    /// Logo top-left y.
    pub logo_y: f32,
    /// Logo edge length.
    pub logo_size: f32,
    /// Logo opacity.
    pub logo_alpha: f32,
    /// Main rim highlight (path data in glass-local px).
    pub rim_a: String,
    /// Opposite, dimmer rim highlight.
    pub rim_b: String,
    /// Rim highlight opacity.
    pub rim_alpha: f32,
    /// Wide, faint part of the light band.
    pub band_a: String,
    /// Narrow, brighter core of the light band.
    pub band_b: String,
    /// Band opacity.
    pub band_alpha: f32,
    /// Opacity of the main screen fading in underneath.
    pub main_opacity: f32,
    /// The splash is over; hide it and stop the timer.
    pub done: bool,
}

/// Computes the splash at time `t` seconds.
pub fn frame(t: f32) -> Frame {
    let t = t.max(0.0);
    let s = spring(t, SPRING_PERIOD);
    // release: the glass lets go, grows slightly and dissolves
    let e = smoothstep(2.4, 2.8, t);
    // settle: the bare logo moves into the header while the main screen fades in
    let k = smootherstep(2.6, TOTAL, t);

    let size = TILE * (0.2 + 0.8 * s) * (1.0 + 0.1 * e);
    let (cx, cy) = (CENTER.0, CENTER.1 - 26.0 * (1.0 - s));
    let radius = lerp(size * 0.5, size * 0.235, smoothstep(0.1, 0.55, t));
    let glass_x = cx - size / 2.0;
    let glass_y = cy - size / 2.0;
    let glass_alpha = smoothstep(0.0, 0.1, t) * (1.0 - e);

    let rt = (t - 0.2) / 0.9;
    let (ripple_size, ripple_alpha) = if (0.0..=1.0).contains(&rt) {
        let grow = 1.0 - (1.0 - rt).powi(3);
        (TILE * (1.0 + 0.75 * grow), 0.35 * (1.0 - rt).powi(2))
    } else {
        (TILE, 0.0)
    };

    let shadow_size = size * 1.5;
    let shadow_alpha = 0.6 * s * (1.0 - e);

    let glide = lerp(2.6, 1.0, smootherstep(0.05, 2.35, t));
    let splash_logo = TILE * LOGO_FRAC * glide;
    let (hx, hy, hs) = HEADER_LOGO;
    let logo_size = lerp(splash_logo, hs, k);
    let lcx = lerp(cx, hx + hs / 2.0, k);
    let lcy = lerp(cy, hy + hs / 2.0, k);

    // The renderer clips rectangles only, so clip to the square inscribed in
    // the rounded tile (its corners touch the corner arcs).
    let inset = radius * (1.0 - 1.0 / SQRT_2);
    let (gx, gy, gw) = (glass_x + inset, glass_y + inset, size - 2.0 * inset);

    let rim_alpha = 0.9 * smoothstep(0.18, 0.6, t) * (1.0 - e);
    let phase = 0.90 + 0.06 * t;
    let p = smoothstep(0.6, 2.0, t);

    Frame {
        glass_x,
        glass_y,
        glass_size: size,
        glass_radius: radius,
        glass_alpha,
        ripple_x: CENTER.0 - ripple_size / 2.0,
        ripple_y: CENTER.1 - ripple_size / 2.0,
        ripple_size,
        ripple_alpha,
        shadow_x: cx - shadow_size / 2.0,
        shadow_y: cy + size * 0.32 - shadow_size / 2.0,
        shadow_size,
        shadow_alpha,
        clip_x: lerp(gx, 0.0, e),
        clip_y: lerp(gy, 0.0, e),
        clip_w: lerp(gw, WIN_W, e),
        clip_h: lerp(gw, WIN_H, e),
        logo_x: lcx - logo_size / 2.0,
        logo_y: lcy - logo_size / 2.0,
        logo_size,
        logo_alpha: smoothstep(0.1, 0.45, t),
        rim_a: rim_arc_path(size, radius, 1.1, phase, 0.20),
        rim_b: rim_arc_path(size, radius, 1.1, phase + 0.5, 0.12),
        rim_alpha,
        band_a: band_path(size, radius, lerp(-0.25, 1.25, p), size * 0.16),
        band_b: band_path(size, radius, lerp(-0.25, 1.25, p), size * 0.055),
        band_alpha: (PI * p).sin().max(0.0) * (1.0 - e),
        main_opacity: k,
        done: t >= TOTAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f32, b: f32, eps: f32) -> bool {
        (a - b).abs() <= eps
    }

    #[test]
    fn spring_is_monotonic_without_overshoot() {
        assert_eq!(spring(0.0, SPRING_PERIOD), 0.0);
        assert_eq!(spring(-1.0, SPRING_PERIOD), 0.0);
        let mut prev = 0.0;
        for i in 1..=300 {
            let v = spring(i as f32 * 0.01, SPRING_PERIOD);
            assert!(v >= prev && v <= 1.0, "t={} v={v}", i as f32 * 0.01);
            prev = v;
        }
        // one period in, the critically damped spring is within ~1.5 % of rest
        assert!(spring(SPRING_PERIOD, SPRING_PERIOD) > 0.98);
        assert!(close(spring(3.0, SPRING_PERIOD), 1.0, 1e-6));
    }

    #[test]
    fn spring_matches_closed_form() {
        let w = TAU / 0.42;
        let t = 0.1;
        let expect = 1.0 - (-w * t).exp() * (1.0 + w * t);
        assert!(close(spring(t, 0.42), expect, 1e-6));
    }

    #[test]
    fn smoothsteps_hit_endpoints_and_midpoint() {
        for f in [smoothstep, smootherstep] {
            assert_eq!(f(1.0, 2.0, 0.0), 0.0);
            assert_eq!(f(1.0, 2.0, 1.0), 0.0);
            assert_eq!(f(1.0, 2.0, 2.0), 1.0);
            assert_eq!(f(1.0, 2.0, 9.0), 1.0);
            assert!(close(f(1.0, 2.0, 1.5), 0.5, 1e-6));
        }
        // smootherstep is flatter at the ends than smoothstep
        assert!(smootherstep(0.0, 1.0, 0.1) < smoothstep(0.0, 1.0, 0.1));
    }

    #[test]
    fn perimeter_points_lie_on_the_rounded_rect() {
        let (w, h, r) = (100.0, 60.0, 20.0);
        for i in 0..400 {
            let (x, y) = rounded_rect_point(w, h, r, i as f32 / 400.0);
            assert!((-1e-3..=w + 1e-3).contains(&x) && (-1e-3..=h + 1e-3).contains(&y));
            // distance to the inner "core" rectangle must equal r
            let qx = (x - w / 2.0).abs() - (w / 2.0 - r);
            let qy = (y - h / 2.0).abs() - (h / 2.0 - r);
            let d = qx.max(0.0).hypot(qy.max(0.0)) + qx.max(qy).min(0.0);
            assert!(close(d, r, 1e-3), "i={i} ({x},{y}) d={d}");
        }
        assert_eq!(rounded_rect_point(w, h, r, 0.0), (r, 0.0));
        let a = rounded_rect_point(w, h, r, 0.25);
        let b = rounded_rect_point(w, h, r, 1.25);
        assert!(close(a.0, b.0, 1e-3) && close(a.1, b.1, 1e-3));
    }

    #[test]
    fn circle_case_is_a_circle() {
        for i in 0..64 {
            let (x, y) = rounded_rect_point(50.0, 50.0, 25.0, i as f32 / 64.0);
            assert!(close((x - 25.0).hypot(y - 25.0), 25.0, 1e-3));
        }
    }

    fn area(poly: &[(f32, f32)]) -> f32 {
        let mut a = 0.0;
        for i in 0..poly.len() {
            let (p, q) = (poly[i], poly[(i + 1) % poly.len()]);
            a += p.0 * q.1 - q.0 * p.1;
        }
        a / 2.0
    }

    #[test]
    fn convex_clip_of_square_by_square() {
        let clip = [(0.0, 0.0), (10.0, 0.0), (10.0, 10.0), (0.0, 10.0)];
        let subj = [(5.0, 5.0), (15.0, 5.0), (15.0, 15.0), (5.0, 15.0)];
        let out = clip_convex(&subj, &clip);
        assert!(close(area(&out).abs(), 25.0, 1e-3));
        let outside = [(20.0, 20.0), (30.0, 20.0), (30.0, 30.0)];
        assert!(clip_convex(&outside, &clip).is_empty());
    }

    #[test]
    fn band_is_inside_tile_and_empty_off_tile() {
        let full = band_path(100.0, 24.0, 0.5, 10.0);
        assert!(full.starts_with('M') && full.ends_with('Z'));
        for tok in full.split(|c: char| c.is_ascii_alphabetic() || c == ' ') {
            if let Ok(v) = tok.parse::<f32>() {
                assert!((-0.01..=100.01).contains(&v), "{v}");
            }
        }
        assert_eq!(band_path(100.0, 24.0, -1.0, 10.0), "M0 0");
        assert_eq!(band_path(100.0, 24.0, 2.0, 10.0), "M0 0");
    }

    #[test]
    fn rim_arc_has_all_samples() {
        let p = rim_arc_path(128.0, 30.0, 1.0, 0.9, 0.2);
        assert_eq!(p.matches('L').count(), 28);
        assert!(p.starts_with('M'));
    }

    #[test]
    fn timeline_start() {
        let f = frame(0.0);
        assert!(
            close(f.glass_size, TILE * 0.2, 1e-3),
            "starts at ~20 % size"
        );
        assert!(
            close(f.glass_radius, f.glass_size / 2.0, 1e-3),
            "starts as a circle"
        );
        assert!(
            close(f.logo_size, TILE * LOGO_FRAC * 2.6, 1e-3),
            "logo starts 2.6x"
        );
        assert_eq!(f.glass_alpha, 0.0);
        assert_eq!(f.main_opacity, 0.0);
        assert!(!f.done);
    }

    #[test]
    fn timeline_landed_tile_is_squircle_with_glass() {
        let f = frame(1.2);
        assert!(close(f.glass_size, TILE, 0.5));
        assert!(close(f.glass_radius, TILE * 0.235, 0.5));
        assert!(f.glass_alpha > 0.99 && f.rim_alpha > 0.8);
        assert!(f.band_alpha > 0.0);
        // the clip square sits inside the glass
        assert!(f.clip_x > f.glass_x && f.clip_x + f.clip_w < f.glass_x + f.glass_size);
    }

    #[test]
    fn logo_glides_down_monotonically_until_release() {
        let mut prev = f32::MAX;
        for i in 0..=46 {
            let f = frame(i as f32 * 0.05);
            assert!(f.logo_size <= prev + 1e-3);
            prev = f.logo_size;
        }
        assert!(close(frame(2.4).logo_size, TILE * LOGO_FRAC, 0.01));
    }

    #[test]
    fn glass_dissolves_and_logo_settles_into_header() {
        let f = frame(2.85);
        assert_eq!(f.glass_alpha, 0.0);
        assert_eq!(f.rim_alpha, 0.0);
        let end = frame(TOTAL);
        assert!(end.done);
        assert_eq!(end.main_opacity, 1.0);
        let (hx, hy, hs) = HEADER_LOGO;
        assert!(close(end.logo_x, hx, 1e-3) && close(end.logo_y, hy, 1e-3));
        assert!(close(end.logo_size, hs, 1e-3));
        // the clip has opened up to the whole window
        assert!(close(end.clip_w, WIN_W, 1e-3) && close(end.clip_h, WIN_H, 1e-3));
    }

    #[test]
    fn rim_light_turns() {
        assert_ne!(frame(1.0).rim_a, frame(2.0).rim_a);
    }
}
