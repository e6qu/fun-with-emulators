// One window showing index.html: the application tests check that it is
// drawn, magenta with "fwe" in green.
const { app, BrowserWindow } = require("electron");
const path = require("node:path");

app.whenReady().then(() => {
  const win = new BrowserWindow({ width: 800, height: 600, title: "fwe-hello" });
  win.loadFile(path.join(__dirname, "index.html"));
  win.webContents.on("did-finish-load", () => console.log("fwe-hello: page loaded"));
});

app.on("window-all-closed", () => app.quit());
