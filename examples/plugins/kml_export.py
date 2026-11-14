"""Example Lumos exporter plugin: one placemark per host, for Google Earth.

Install by copying this file into ``~/.config/lumos/plugins/`` and running
``lumos report plugin ENGAGEMENT.sqlite hosts.kml --name kml``.
"""

import sqlite3

PLUGIN_API = 1
PLUGIN_KIND = "exporter"
PLUGIN_NAME = "kml"


def export(database: str, output: str) -> str:
    """Write placemarks with no coordinates: the names are the evidence."""
    conn = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        rows = [
            (str(label or address), str(hostname or ""))
            for address, hostname, label in conn.execute(
                "SELECT a.normalized_value, h.hostname, tn.label"
                " FROM addresses a"
                " LEFT JOIN observation_addresses oa ON oa.address_id = a.id"
                " LEFT JOIN host_observations h ON h.id = oa.host_observation_id"
                " LEFT JOIN topology_nodes tn ON tn.entity_id = h.device_id"
                " WHERE a.kind = 'ipv4' ORDER BY a.normalized_value"
            )
        ]
    finally:
        conn.close()
    with open(output, "w", encoding="utf-8") as stream:
        stream.write('<?xml version="1.0" encoding="UTF-8"?>\n<kml><Document>\n')
        for name, hostname in rows:
            description = f"<description>{hostname}</description>" if hostname else ""
            stream.write(f"<Placemark><name>{name}</name>{description}</Placemark>\n")
        stream.write("</Document></kml>\n")
    return f"wrote {len(rows)} placemark(s) to {output}"
