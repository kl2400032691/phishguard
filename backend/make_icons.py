from PIL import Image, ImageDraw
import os

os.makedirs("../extension/icons", exist_ok=True)
for size in (16, 48, 128):
    s = size * 4                      # draw large, shrink for smooth edges
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    shield = [(0.5*s, 0.06*s), (0.88*s, 0.2*s), (0.88*s, 0.52*s),
              (0.5*s, 0.95*s), (0.12*s, 0.52*s), (0.12*s, 0.2*s)]
    d.polygon(shield, fill=(31, 58, 147, 255))
    d.line([(0.32*s, 0.5*s), (0.46*s, 0.64*s), (0.69*s, 0.34*s)],
           fill=(255, 255, 255, 255), width=max(int(0.09*s), 2), joint="curve")
    img.resize((size, size), Image.LANCZOS).save(f"../extension/icons/icon{size}.png")
print("done")