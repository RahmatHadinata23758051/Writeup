#!/usr/bin/env python3
import base64
import io
import re
import zlib
from pathlib import Path

import cv2
import numpy as np
from PIL import Image

# This PNG is the dense stack of the four recovered SSTV sideband strips.
# It is kept as a fallback so the solve step is reproducible even if the
# temporary crop PNG files are cleaned up. If crop_0.png..crop_3.png exist,
# the script rebuilds the same stack from them.
EMBEDDED_STACK_B85 = """
c-jF#2*3A<P)<h;3K|Lk000e1NJLTq00961007bm00000fS5rl000OFNkl<Zc%1EB?YgBZ2$u8A{ogX@M_Ot~fF`z=@0r<qRw)r7pSBKQ@BkE_kUUDCMCubwR)qibQ~nmV0K6IS#uk7#1K#*~0sNbE9olVGD9_S9ts+Fz75Mf<{o@*7aQqcME`WY~Tmb!X?8gPrk1YUi2D~xL4OSo>9-H?yrm#kU%`PKW(tv)SX241UaKRRUHv`_-0`O+Q8<X8&oxE{|pG_c#)pC6_0IJ^yTnf}HErFkp1GWZuTy!M?Yz^?Z=qv${PnRuwPQtV}piFKR&CyVvWSgS~th5ANum#}FfH$@PyczJuN&;|+17=r+74d*%=MY^oW-nG@B@Lj#>cx%&y76%V?Dlv!wg9{t@P^YKA$DsI>lMqH*qu@Tyar4wh+ser0U*R5+0%#XJVW3m#^z}N9(Ng1Qy=m(0idO~?7BF}_DE-z03beSGlAAj2%#xE2`1JAA8(#DX#BQG2q6RjgM3%oDca6xAYcd(5HQ_id9TMOv}l4wXeJ!IiOQc-`vVhgK=zBd$u5g#z~ngKxi8*j(G1vukT(O~SWp0e+6Eje93V!8*^l&Vc8_?L8>F*A8dF7}3xqT+NyQ!~RyvxaBz1nwf;M0-mJons%Qs*^#Pdf0fB*n-^7SKxfKWg4+Xb>*T)p4`V{Fb3y3&+9`E5)Cgm8xWx+Rbj0E7?%mW0TecLEC7Z2&vd!v>^5ODq99>|t{f(p%{;gi;kTM0LIEz@_?FE-#3S2P3&t!@-vMl2<h?feJSg`E5#czan(p=7VXxjLb1Q;Qd~nRxIEv0*KtFB1W{Ditt8aX@s2QN9ifAECD!`0Qq9zU)U^tD`2>6bD)tzh7j6p=`?_PMlR1SAY67Zw~S?}@CXkOQtcd~EzZZhVgxhe!rL=Q%`GgAKXEq(PMmB2R5tIj2#ulXUq!#~G1wdgn+9+u4auR8%~2rSm>HLgJp3iLy^vM|Fr+91^8n^J6)&#84=~Q-5$h`$t1#!`LeN?PKnMY_NWM--P%PU<<JupU+cMbzT35@Z+h}E7DQi8md`8;k0F}U>BFQ^Pve7Z?Y@H3Exy-qfnj}-kCUvod@-i9?c=Ao$4e&+4!OMlES8=Hk048H1%IY<EaQbi3Gb{ljp^cU`OUsVb_xf`spQXP`t9@v7x^%(p3K()>zU0KsWP=0=JyDiTQ+T@~w5k`Z8GB6t8qJc79VXBYBdCIMZDA^%gzF#2k9aVJ7+9WY61!K%fiwxP*#JHuD#ys_71cm-u#;1cslhq%9RcLYEjN=*oXDZWj9~iojtv0Qnl%&w4d_||ni4My`q5YP;!@{kvK0_^P&%kAiNRT7>H=OR<IG$^9>ikt>piHKzz~kozP?DYs2-(%P1?Djbc2U8p;=Qfd{xcTUoE=xrzBtf28pL+NQOfN%0;TVDf|6bhQX&fIxI}AE#%P&xa|*MX8L@co@RY(A}L8d8A~r<F*SAZ37O^>JM|<%o+}B`9+UNv^w9yiK)rP7J5WoOZ+UABgl4Qo08qN`^RQrQhw-MWJj9Ws4@O-EZ$VWEMh%dJy2HKrvA#>PwYiIXE%W#>kFzMAZDn!En0D#B3B1zZ#<Q+0059dr+@&Ku%~5uq$OPCkJvRC;r%){ds7+UdSp(YLwm8P10i#f^b^d*t!4Wsq*SQK0^=AyJf}Bmy_d%sUMS+KFp{9~gHaNd@%~3IFAR1L@D0)f~eWszPA2w<-ea%q;ilP->NAcVycW$F9F?xMm+w9;hB_6EY293RL@u>>K;P~%en|p%;$r2c^0Z*O|!_~5XX$fdBJ{z1<#~6n30$8>sMC0vx0BLyYlLmVBIn@I)y)si#rhOXyk*zDU1SFiWl+u)O&C%{s!V2gS!06tG3#Pv}I1wUgfBcOR79weTy*<9n#s2aV5M9g^3e!1V-F79XuqP#i=%M!Pa{VQs=?fU}myMtZTL9h+cw-B|n*nchHAW;GB}DB@$rwd7RKw8kRfH=3Ca1#-;B^i77`6a9=B`)XG2rJlU`S)+)`!oI8VHFlB5<U<Q;hURc!5UWSx->0yG;^Eh$4q=13Kn@GY+V*HK1ee)_`GLIO1y>z&2Yg^t!6TB-rg4{ElC`fy(w?6?t_vV?c9s4qjep>zBn@^h@XCouSY51=jPNAJ>3>tfT=hJ5IXNVbZ_wIU?!*L>^A@K8i*x>$}01u?67GKp#Hm21ny_fzW9Dyax1R^4IG}u&z?Xk)(6_dR5pCcIgg_7GJLl{|RgXcr)OQEdXx@yfN{Aw<m_8Mc9FZBV|>%;}r=>9xUp7a!?hJkHdQjcr)OQEdXx@ys-t~&44#-RbhcwZ@4nDSK9HCsiIcAM00dEMh4T{HNkEQdkM_F+|PH1N5i=}+6_aJta!UrMDODo(2w5}z`%EgzKQ+LP>J7*1ALdj0&zgs_XrJx;pI@t-dOfs8Jf;YOQ2sp6cp0Xm5iW^fmlfZF4zL_X22UOxj`2nxsnD*jG)DhaC2<0%)AA*4y>sE@>5F+E5!jWSZN8kU?n5yf~^7G40vOG0lfUprIX#D=x*qWuf{oYU!7F#Q(j*KSnS?lH-(Q2pdUL9@MgdpKc5TO+@QG^$$ud)`^A4WJ$45!n?O#^21h^oVf3~Q@MgdpTL9h+WcY=m=$sb@HTWN8Wy-=LU>9!y0000<MNUMnLSTX}($0n
""".strip()


def load_or_build_stack() -> np.ndarray:
    stack_path = Path("stack_content.png")
    if stack_path.exists():
        return np.array(Image.open(stack_path).convert("L"))

    crops = [Path(f"crop_{i}.png") for i in range(4)]
    if all(p.exists() for p in crops):
        # Dense rows only. The original crop_1 has a large blank area above it.
        rows = [(2, 47), (72, 132), (2, 62), (2, 47)]
        parts = []
        for p, (a, b) in zip(crops, rows):
            parts.append(np.array(Image.open(p).convert("L"))[a:b, :])
        stack = np.vstack(parts)
        Image.fromarray(stack).save(stack_path)
        return stack

    raw = zlib.decompress(base64.b85decode(EMBEDDED_STACK_B85))
    return np.array(Image.open(io.BytesIO(raw)).convert("L"))


def set_finder(mat: np.ndarray, r: int, c: int) -> None:
    """Repair a QR finder pattern including its white separator."""
    n = mat.shape[0]
    for yy in range(r - 1, r + 8):
        for xx in range(c - 1, c + 8):
            if not (0 <= yy < n and 0 <= xx < n):
                continue
            y = yy - r
            x = xx - c
            black = (
                0 <= x <= 6
                and 0 <= y <= 6
                and (x in (0, 6) or y in (0, 6) or (2 <= x <= 4 and 2 <= y <= 4))
            )
            mat[yy, xx] = 1 if black else 0


def render_qr(mat: np.ndarray, scale: int = 12) -> np.ndarray:
    n = mat.shape[0]
    out = np.full(((n + 8) * scale, (n + 8) * scale), 255, dtype=np.uint8)
    for r in range(n):
        for c in range(n):
            if mat[r, c]:
                out[(r + 4) * scale : (r + 5) * scale, (c + 4) * scale : (c + 5) * scale] = 0
    return out


def recover_qr(stack: np.ndarray) -> str:
    # The recovered barcode is QR version 3: 29x29 modules.
    # The SSTV damage destroys the upper-left finder, so we repair the fixed QR
    # structures before asking OpenCV to decode it.
    detector = cv2.QRCodeDetector()
    n = 29

    for x0 in np.linspace(43.0, 47.0, 17):
        for y0 in np.linspace(-1.0, 3.0, 17):
            for module in np.linspace(7.0, 7.35, 36):
                mat = np.zeros((n, n), dtype=np.uint8)
                for r in range(n):
                    for c in range(n):
                        x = int(x0 + (c + 0.5) * module)
                        y = int(y0 + (r + 0.5) * module)
                        if 0 <= y < stack.shape[0] and 0 <= x < stack.shape[1]:
                            mat[r, c] = 1 if stack[y, x] < 128 else 0

                set_finder(mat, 0, 0)
                set_finder(mat, 0, n - 7)
                set_finder(mat, n - 7, 0)

                for i in range(8, n - 8):
                    bit = 1 if i % 2 == 0 else 0
                    mat[6, i] = bit
                    mat[i, 6] = bit

                # Fixed dark module for version 3 QR.
                mat[21, 8] = 1

                qr = render_qr(mat)
                text, _, _ = detector.detectAndDecode(qr)
                if text:
                    Image.fromarray(qr).save("recovered_qr.png")
                    return text

    raise RuntimeError("QR reconstruction failed")


def main() -> None:
    stack = load_or_build_stack()
    text = recover_qr(stack)
    m = re.search(r"ASIS\{[^}]+\}", text)
    if not m:
        raise RuntimeError(f"decoded QR did not contain a flag: {text!r}")
    print(f"<FLAG>{m.group(0)}</FLAG>")


if __name__ == "__main__":
    main()
