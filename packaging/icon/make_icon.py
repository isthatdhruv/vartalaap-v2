"""Generate the Vartalaap app icon.

Two overlapping speech bubbles on the app's own accent gradient — the name
means "conversation", and the overlap reads as two peers talking directly to
each other, which is the whole product. Drawn at 4x and downsampled so the
curves and the tail joins stay clean at 32px.
"""

from PIL import Image, ImageDraw

S = 1024
SS = 4  # supersample factor
W = S * SS

# App palette (App.css :root --accent, and the avatar gradient it pairs with).
TOP = (109, 106, 254)
BOT = (155, 92, 246)


def rounded_rect_mask(size, box, radius):
    m = Image.new("L", size, 0)
    ImageDraw.Draw(m).rounded_rectangle(box, radius=radius, fill=255)
    return m


def bubble(draw, box, radius, tail, fill):
    """A speech bubble: rounded rect plus a triangular tail."""
    draw.rounded_rectangle(box, radius=radius, fill=fill)
    draw.polygon(tail, fill=fill)


# --- background: vertical gradient clipped to a squircle-ish rounded square ---
grad = Image.new("RGB", (1, W))
for y in range(W):
    t = y / (W - 1)
    grad.putpixel(
        (0, y),
        (
            round(TOP[0] + (BOT[0] - TOP[0]) * t),
            round(TOP[1] + (BOT[1] - TOP[1]) * t),
            round(TOP[2] + (BOT[2] - TOP[2]) * t),
        ),
    )
grad = grad.resize((W, W))

icon = Image.new("RGBA", (W, W), (0, 0, 0, 0))
icon.paste(grad, (0, 0), rounded_rect_mask((W, W), (0, 0, W - 1, W - 1), int(W * 0.225)))

# --- bubbles ---
layer = Image.new("RGBA", (W, W), (0, 0, 0, 0))
d = ImageDraw.Draw(layer)

u = W / 1024.0  # design in 1024-space, scale up

# Back bubble: the peer on the other end. Translucent so the front one reads
# as nearer rather than as a flat cut-out.
bubble(
    d,
    (int(330 * u), int(250 * u), int(800 * u), int(560 * u)),
    radius=int(78 * u),
    tail=[
        (int(736 * u), int(546 * u)),
        (int(790 * u), int(652 * u)),
        (int(636 * u), int(546 * u)),
    ],
    fill=(255, 255, 255, 115),
)

# Front bubble: us.
bubble(
    d,
    (int(224 * u), int(400 * u), int(694 * u), int(716 * u)),
    radius=int(78 * u),
    tail=[
        (int(300 * u), int(702 * u)),
        (int(246 * u), int(812 * u)),
        (int(410 * u), int(702 * u)),
    ],
    fill=(255, 255, 255, 255),
)

# Three dots in the front bubble — "someone is saying something".
dot_y = int(558 * u)
r = int(31 * u)
for cx in (int(348 * u), int(459 * u), int(570 * u)):
    d.ellipse((cx - r, dot_y - r, cx + r, dot_y + r), fill=(112, 100, 250, 255))

icon = Image.alpha_composite(icon, layer)
icon = icon.resize((S, S), Image.LANCZOS)

out = "packaging/icon/vartalaap-icon-1024.png"
icon.save(out)
print("wrote", out)
# Regenerate the shipped icon set from it with:
#   cd app && npm run tauri icon ../packaging/icon/vartalaap-icon-1024.png
