#!/usr/bin/env python3
"""Solve Occultation Window using a self-contained near-Earth SGP4 propagator."""

from __future__ import annotations

import csv
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

TAU = 2.0 * math.pi
X2O3 = 2.0 / 3.0

# WGS-72 constants used by the classic SGP4 model.
MU72 = 398600.8
RE72 = 6378.135
XKE = 60.0 / math.sqrt(RE72**3 / MU72)
J2 = 0.001082616
J3 = -0.00000253881
J4 = -0.00000165597
J3OJ2 = J3 / J2

# WGS-84 constants used for ECEF -> geodetic conversion.
RE84 = 6378.137
F84 = 1.0 / 298.257223563
E2_84 = F84 * (2.0 - F84)


@dataclass
class TLE:
    epoch: datetime
    inclination: float
    raan: float
    eccentricity: float
    arg_perigee: float
    mean_anomaly: float
    mean_motion: float  # radians/minute
    bstar: float


@dataclass
class Station:
    latitude_deg: float
    longitude_deg: float
    ecef_km: tuple[float, float, float]
    horizon_deg: float
    fix_accuracy_deg: float


def parse_tle_exponential(field: str) -> float:
    """Parse implied-decimal TLE notation such as '10000-3'."""
    field = field.strip()
    match = re.fullmatch(r"([+-]?)(\d{5})([+-]\d+)", field)
    if not match:
        raise ValueError(f"unsupported TLE exponential field: {field!r}")
    sign = -1.0 if match.group(1) == "-" else 1.0
    mantissa = int(match.group(2)) / 100000.0
    exponent = int(match.group(3))
    return sign * mantissa * (10.0**exponent)


def read_tle(path: Path) -> TLE:
    lines = [line.rstrip("\n") for line in path.read_text().splitlines() if line.strip()]
    if len(lines) < 3:
        raise ValueError("expected a name line plus two TLE lines")
    line1, line2 = lines[-2], lines[-1]

    epoch_field = line1[18:32].strip()
    yy = int(epoch_field[:2])
    year = 1900 + yy if yy >= 57 else 2000 + yy
    day_of_year = float(epoch_field[2:])
    epoch = datetime(year, 1, 1, tzinfo=timezone.utc) + timedelta(days=day_of_year - 1.0)

    parts = line2.split()
    if len(parts) < 8:
        raise ValueError("malformed TLE line 2")

    return TLE(
        epoch=epoch,
        inclination=math.radians(float(parts[2])),
        raan=math.radians(float(parts[3])),
        eccentricity=float(f"0.{parts[4]}"),
        arg_perigee=math.radians(float(parts[5])),
        mean_anomaly=math.radians(float(parts[6])),
        mean_motion=float(parts[7]) * TAU / 1440.0,
        bstar=parse_tle_exponential(line1[53:61]),
    )


def read_station(path: Path) -> Station:
    text = path.read_text()

    def number(pattern: str) -> float:
        match = re.search(pattern, text, flags=re.MULTILINE)
        if not match:
            raise ValueError(f"station field not found: {pattern}")
        return float(match.group(1))

    return Station(
        latitude_deg=number(r"geodetic latitude\s*:\s*([+-]?\d+(?:\.\d+)?)"),
        longitude_deg=number(r"geodetic longitude\s*:\s*([+-]?\d+(?:\.\d+)?)"),
        ecef_km=(
            number(r"ECEF x\s*:\s*([+-]?\d+(?:\.\d+)?)"),
            number(r"ECEF y\s*:\s*([+-]?\d+(?:\.\d+)?)"),
            number(r"ECEF z\s*:\s*([+-]?\d+(?:\.\d+)?)"),
        ),
        horizon_deg=number(r"horizon mask\s*:\s*([+-]?\d+(?:\.\d+)?)"),
        fix_accuracy_deg=number(r"fix accuracy\s*:\s*([+-]?\d+(?:\.\d+)?)"),
    )


def sgp4_initialize(tle: TLE) -> dict[str, float]:
    ecco = tle.eccentricity
    argpo = tle.arg_perigee
    inclo = tle.inclination
    mo = tle.mean_anomaly
    no_kozai = tle.mean_motion
    nodeo = tle.raan
    bstar = tle.bstar

    cosio = math.cos(inclo)
    cosio2 = cosio * cosio
    sinio = math.sin(inclo)
    eccsq = ecco * ecco
    omeosq = 1.0 - eccsq
    rteosq = math.sqrt(omeosq)

    ak = (XKE / no_kozai) ** X2O3
    d1 = 0.75 * J2 * (3.0 * cosio2 - 1.0) / (rteosq * omeosq)
    delta = d1 / (ak * ak)
    adel = ak * (1.0 - delta * delta - delta * (1.0 / 3.0 + 134.0 * delta * delta / 81.0))
    delta = d1 / (adel * adel)
    no_unkozai = no_kozai / (1.0 + delta)

    ao = (XKE / no_unkozai) ** X2O3
    po = ao * omeosq
    posq = po * po
    rp = ao * (1.0 - ecco)
    con42 = 1.0 - 5.0 * cosio2
    con41 = 3.0 * cosio2 - 1.0

    ss = 78.0 / RE72 + 1.0
    qzms2t = ((120.0 - 78.0) / RE72) ** 4
    perigee_km = (rp - 1.0) * RE72
    sfour = ss
    qzms24 = qzms2t
    if perigee_km < 156.0:
        sfour = perigee_km - 78.0
        if perigee_km < 98.0:
            sfour = 20.0
        qzms24 = ((120.0 - sfour) / RE72) ** 4
        sfour = sfour / RE72 + 1.0

    pinvsq = 1.0 / posq
    tsi = 1.0 / (ao - sfour)
    eta = ao * ecco * tsi
    etasq = eta * eta
    eeta = ecco * eta
    psisq = abs(1.0 - etasq)
    coef = qzms24 * tsi**4
    coef1 = coef / psisq**3.5

    cc2 = coef1 * no_unkozai * (
        ao * (1.0 + 1.5 * etasq + eeta * (4.0 + etasq))
        + 0.375 * J2 * tsi / psisq * con41 * (8.0 + 3.0 * etasq * (8.0 + etasq))
    )
    cc1 = bstar * cc2
    cc3 = -2.0 * coef * tsi * J3OJ2 * no_unkozai * sinio / ecco if ecco > 1.0e-4 else 0.0
    x1mth2 = 1.0 - cosio2
    cc4 = 2.0 * no_unkozai * coef1 * ao * omeosq * (
        eta * (2.0 + 0.5 * etasq)
        + ecco * (0.5 + 2.0 * etasq)
        - J2
        * tsi
        / (ao * psisq)
        * (
            -3.0 * con41 * (1.0 - 2.0 * eeta + etasq * (1.5 - 0.5 * eeta))
            + 0.75
            * x1mth2
            * (2.0 * etasq - eeta * (1.0 + etasq))
            * math.cos(2.0 * argpo)
        )
    )
    cc5 = 2.0 * coef1 * ao * omeosq * (1.0 + 2.75 * (etasq + eeta) + eeta * etasq)

    cosio4 = cosio2 * cosio2
    temp1 = 1.5 * J2 * pinvsq * no_unkozai
    temp2 = 0.5 * temp1 * J2 * pinvsq
    temp3 = -0.46875 * J4 * pinvsq * pinvsq * no_unkozai
    mdot = no_unkozai + 0.5 * temp1 * rteosq * con41 + 0.0625 * temp2 * rteosq * (
        13.0 - 78.0 * cosio2 + 137.0 * cosio4
    )
    argpdot = (
        -0.5 * temp1 * con42
        + 0.0625 * temp2 * (7.0 - 114.0 * cosio2 + 395.0 * cosio4)
        + temp3 * (3.0 - 36.0 * cosio2 + 49.0 * cosio4)
    )
    xhdot1 = -temp1 * cosio
    nodedot = xhdot1 + (
        0.5 * temp2 * (4.0 - 19.0 * cosio2) + 2.0 * temp3 * (3.0 - 7.0 * cosio2)
    ) * cosio

    omgcof = bstar * cc3 * math.cos(argpo)
    xmcof = -X2O3 * coef * bstar / eeta if ecco > 1.0e-4 else 0.0
    nodecf = 3.5 * omeosq * xhdot1 * cc1
    t2cof = 1.5 * cc1
    denominator = 1.0 + cosio
    if abs(denominator) < 1.5e-12:
        denominator = 1.5e-12
    xlcof = -0.25 * J3OJ2 * sinio * (3.0 + 5.0 * cosio) / denominator
    aycof = -0.5 * J3OJ2 * sinio
    delmo = (1.0 + eta * math.cos(mo)) ** 3
    sinmao = math.sin(mo)
    x7thm1 = 7.0 * cosio2 - 1.0

    isimp = 1.0 if rp < (220.0 / RE72 + 1.0) else 0.0
    d2 = d3 = d4 = t3cof = t4cof = t5cof = 0.0
    if not isimp:
        cc1sq = cc1 * cc1
        d2 = 4.0 * ao * tsi * cc1sq
        temp = d2 * tsi * cc1 / 3.0
        d3 = (17.0 * ao + sfour) * temp
        d4 = 0.5 * temp * ao * tsi * (221.0 * ao + 31.0 * sfour) * cc1
        t3cof = d2 + 2.0 * cc1sq
        t4cof = 0.25 * (3.0 * d3 + cc1 * (12.0 * d2 + 10.0 * cc1sq))
        t5cof = 0.2 * (
            3.0 * d4
            + 12.0 * cc1 * d3
            + 6.0 * d2 * d2
            + 15.0 * cc1sq * (2.0 * d2 + cc1sq)
        )

    return locals()


def sgp4_position(model: dict[str, float], minutes_since_epoch: float) -> tuple[float, float, float]:
    p = model
    t = minutes_since_epoch

    xmdf = p["mo"] + p["mdot"] * t
    argpdf = p["argpo"] + p["argpdot"] * t
    nodedf = p["nodeo"] + p["nodedot"] * t
    argpm = argpdf
    mm = xmdf
    t2 = t * t
    nodem = nodedf + p["nodecf"] * t2
    tempa = 1.0 - p["cc1"] * t
    tempe = p["bstar"] * p["cc4"] * t
    templ = p["t2cof"] * t2

    if not p["isimp"]:
        delomg = p["omgcof"] * t
        delmtemp = 1.0 + p["eta"] * math.cos(xmdf)
        delm = p["xmcof"] * (delmtemp**3 - p["delmo"])
        correction = delomg + delm
        mm = xmdf + correction
        argpm = argpdf - correction
        t3 = t2 * t
        t4 = t3 * t
        tempa -= p["d2"] * t2 + p["d3"] * t3 + p["d4"] * t4
        tempe += p["bstar"] * p["cc5"] * (math.sin(mm) - p["sinmao"])
        templ += p["t3cof"] * t3 + p["t4cof"] * t4 + p["t5cof"] * t4 * t

    nm = p["no_unkozai"]
    em = p["ecco"] - tempe
    inclm = p["inclo"]
    am = (XKE / nm) ** X2O3 * tempa * tempa
    nm = XKE / am**1.5
    if nm <= 0.0 or not (0.0 <= em < 1.0):
        raise ValueError("invalid propagated orbit")

    mm += p["no_unkozai"] * templ
    xlm = mm + argpm + nodem
    nodem %= TAU
    argpm %= TAU
    xlm %= TAU
    mm = (xlm - argpm - nodem) % TAU

    sinim = math.sin(inclm)
    cosim = math.cos(inclm)
    axnl = em * math.cos(argpm)
    temp = 1.0 / (am * (1.0 - em * em))
    aynl = em * math.sin(argpm) + temp * p["aycof"]
    xl = mm + argpm + nodem + temp * p["xlcof"] * axnl
    u = (xl - nodem) % TAU

    eo1 = u
    for _ in range(10):
        sineo1 = math.sin(eo1)
        coseo1 = math.cos(eo1)
        denominator = 1.0 - coseo1 * axnl - sineo1 * aynl
        step = (u - aynl * coseo1 + axnl * sineo1 - eo1) / denominator
        step = max(-0.95, min(0.95, step))
        eo1 += step
        if abs(step) < 1.0e-12:
            break

    sineo1 = math.sin(eo1)
    coseo1 = math.cos(eo1)
    ecose = axnl * coseo1 + aynl * sineo1
    esine = axnl * sineo1 - aynl * coseo1
    el2 = axnl * axnl + aynl * aynl
    pl = am * (1.0 - el2)
    rl = am * (1.0 - ecose)
    betal = math.sqrt(1.0 - el2)
    temp = esine / (1.0 + betal)
    sinu = am / rl * (sineo1 - aynl - axnl * temp)
    cosu = am / rl * (coseo1 - axnl + aynl * temp)
    su = math.atan2(sinu, cosu)
    sin2u = 2.0 * sinu * cosu
    cos2u = 1.0 - 2.0 * sinu * sinu

    temp = 1.0 / pl
    temp1 = 0.5 * J2 * temp
    temp2 = temp1 * temp
    mrt = rl * (1.0 - 1.5 * temp2 * betal * p["con41"]) + 0.5 * temp1 * p["x1mth2"] * cos2u
    su -= 0.25 * temp2 * p["x7thm1"] * sin2u
    xnode = nodem + 1.5 * temp2 * cosim * sin2u
    xinc = inclm + 1.5 * temp2 * cosim * sinim * cos2u

    sinsu = math.sin(su)
    cossu = math.cos(su)
    snod = math.sin(xnode)
    cnod = math.cos(xnode)
    sini = math.sin(xinc)
    cosi = math.cos(xinc)
    xmx = -snod * cosi
    xmy = cnod * cosi
    ux = xmx * sinsu + cnod * cossu
    uy = xmy * sinsu + snod * cossu
    uz = sini * sinsu

    return mrt * ux * RE72, mrt * uy * RE72, mrt * uz * RE72


def gmst(timestamp: datetime) -> float:
    unix_seconds = timestamp.timestamp()
    jd = 2440587.5 + unix_seconds / 86400.0
    centuries = (jd - 2451545.0) / 36525.0
    degrees = (
        280.46061837
        + 360.98564736629 * (jd - 2451545.0)
        + 0.000387933 * centuries * centuries
        - centuries**3 / 38710000.0
    ) % 360.0
    return math.radians(degrees)


def teme_to_ecef(position_teme: tuple[float, float, float], timestamp: datetime) -> tuple[float, float, float]:
    theta = gmst(timestamp)
    c = math.cos(theta)
    s = math.sin(theta)
    x, y, z = position_teme
    return c * x + s * y, -s * x + c * y, z


def ecef_to_geodetic(position: tuple[float, float, float]) -> tuple[float, float]:
    x, y, z = position
    lon = math.atan2(y, x)
    horizontal = math.hypot(x, y)
    lat = math.atan2(z, horizontal * (1.0 - E2_84))
    for _ in range(8):
        sin_lat = math.sin(lat)
        n = RE84 / math.sqrt(1.0 - E2_84 * sin_lat * sin_lat)
        height = horizontal / math.cos(lat) - n
        lat = math.atan2(z, horizontal * (1.0 - E2_84 * n / (n + height)))
    return math.degrees(lat), math.degrees(lon)


def angular_separation_deg(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    lat1r, lon1r = math.radians(lat1), math.radians(lon1)
    lat2r, lon2r = math.radians(lat2), math.radians(lon2)
    dlat = lat2r - lat1r
    dlon = lon2r - lon1r
    hav = math.sin(dlat / 2.0) ** 2 + math.cos(lat1r) * math.cos(lat2r) * math.sin(dlon / 2.0) ** 2
    return math.degrees(2.0 * math.asin(min(1.0, math.sqrt(hav))))


def elevation_deg(position_ecef: tuple[float, float, float], station: Station) -> float:
    sx, sy, sz = station.ecef_km
    rx = position_ecef[0] - sx
    ry = position_ecef[1] - sy
    rz = position_ecef[2] - sz
    distance = math.sqrt(rx * rx + ry * ry + rz * rz)

    lat = math.radians(station.latitude_deg)
    lon = math.radians(station.longitude_deg)
    up = (math.cos(lat) * math.cos(lon), math.cos(lat) * math.sin(lon), math.sin(lat))
    projection = rx * up[0] + ry * up[1] + rz * up[2]
    return math.degrees(math.asin(projection / distance))


def solve(base_dir: Path) -> str:
    tle = read_tle(base_dir / "asset.tle")
    station = read_station(base_dir / "relay_station.txt")
    model = sgp4_initialize(tle)

    matches: list[dict[str, object]] = []
    with (base_dir / "contacts.csv").open(newline="") as handle:
        for row in csv.DictReader(handle):
            timestamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
            minutes = (timestamp - tle.epoch).total_seconds() / 60.0
            teme = sgp4_position(model, minutes)
            ecef = teme_to_ecef(teme, timestamp)
            predicted_lat, predicted_lon = ecef_to_geodetic(ecef)
            error = angular_separation_deg(
                float(row["lat"]), float(row["lon"]), predicted_lat, predicted_lon
            )
            elevation = elevation_deg(ecef, station)

            if error <= station.fix_accuracy_deg and elevation >= station.horizon_deg:
                matches.append(
                    {
                        "timestamp": timestamp,
                        "token": row["token"],
                        "error": error,
                        "elevation": elevation,
                    }
                )

    matches.sort(key=lambda item: item["timestamp"])
    for match in matches:
        stamp = match["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ")
        print(
            f"{stamp}  token={match['token']}  "
            f"error={match['error']:.6f} deg  elevation={match['elevation']:.3f} deg"
        )

    flag = "".join(str(match["token"]) for match in matches)
    print(f"\nmatched contacts: {len(matches)}")
    print(flag)
    return flag


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    flag = solve(base_dir)
    if not (flag.startswith("uctf{") and flag.endswith("}")):
        raise SystemExit("derived token stream is not a valid uctf flag")


if __name__ == "__main__":
    main()
