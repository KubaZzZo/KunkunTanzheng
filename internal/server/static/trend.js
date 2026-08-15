(function () {
  "use strict";

  function formatBytes(value) {
    var units = ["B", "KiB", "MiB", "GiB", "TiB"];
    var index = 0;
    while (value >= 1024 && index < units.length - 1) {
      value /= 1024;
      index += 1;
    }
    return value.toFixed(value >= 100 || index === 0 ? 0 : 1) + " " + units[index];
  }

  function seriesFor(metric, points) {
    if (metric === "memory") return [{ name: "Memory", color: "#087e8b", values: points.map(function (point) { return point.memory; }) }];
    if (metric === "disk") return [{ name: "Root disk", color: "#bb2d3b", values: points.map(function (point) { return point.disk; }) }];
    if (metric === "network") return [
      { name: "Ingress", color: "#087e8b", values: points.map(function (point) { return point.ingress; }) },
      { name: "Egress", color: "#9467bd", values: points.map(function (point) { return point.egress; }) }
    ];
    return [{ name: "CPU", color: "#e07000", values: points.map(function (point) { return point.cpu; }) }];
  }

  function valueLabel(metric, value) {
    if (metric === "cpu") return value.toFixed(0) + "%";
    if (metric === "network") return formatBytes(value) + "/s";
    return formatBytes(value);
  }

  function element(name, attributes) {
    var node = document.createElementNS("http://www.w3.org/2000/svg", name);
    Object.keys(attributes).forEach(function (key) { node.setAttribute(key, attributes[key]); });
    return node;
  }

  function renderTrend(container, metric) {
    var points;
    try { points = JSON.parse(container.dataset.trend || "[]"); } catch (_) { return; }
    if (!points.length) return;
    var width = 900, height = 280, left = 64, right = 20, top = 20, bottom = 36;
    var plotWidth = width - left - right, plotHeight = height - top - bottom;
    var series = seriesFor(metric, points);
    var maximum = Math.max.apply(null, series.reduce(function (all, item) { return all.concat(item.values); }, [0]));
    maximum = Math.max(maximum, metric === "cpu" ? 100 : 1);
    var svg = element("svg", { viewBox: "0 0 " + width + " " + height, role: "img", "aria-label": "24 hour " + metric + " trend" });
    for (var grid = 0; grid <= 4; grid += 1) {
      var y = top + (plotHeight * grid / 4);
      svg.appendChild(element("line", { x1: left, y1: y, x2: width - right, y2: y, class: "trend-grid" }));
      var label = element("text", { x: left - 8, y: y + 4, class: "trend-axis", "text-anchor": "end" });
      label.textContent = valueLabel(metric, maximum * (1 - grid / 4));
      svg.appendChild(label);
    }
    series.forEach(function (item) {
      var path = item.values.map(function (value, index) {
        var x = left + (points.length === 1 ? plotWidth / 2 : plotWidth * index / (points.length - 1));
        var y = top + plotHeight * (1 - Math.min(value / maximum, 1));
        return (index === 0 ? "M" : "L") + x.toFixed(2) + " " + y.toFixed(2);
      }).join(" ");
      svg.appendChild(element("path", { d: path, fill: "none", stroke: item.color, "stroke-width": "2.5", class: "trend-line" }));
    });
    [0, points.length - 1].forEach(function (index, position) {
      var label = element("text", { x: position === 0 ? left : width - right, y: height - 12, class: "trend-axis", "text-anchor": position === 0 ? "start" : "end" });
      label.textContent = new Date(points[index].received_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      svg.appendChild(label);
    });
    container.replaceChildren(svg);
  }

  function initialize() {
    var container = document.getElementById("trend-chart");
    var selector = document.getElementById("trend-metric");
    if (!container || !selector) return;
    function refresh() { renderTrend(container, selector.value); }
    selector.addEventListener("change", refresh);
    refresh();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initialize);
  else initialize();
}());
