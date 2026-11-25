// One window showing index.html: the application tests check that it is
// drawn, magenta with "fwe" in green. With FWE_QUIT_LOADED set, the app
// quits once its page is loaded: the benchmarks' start-up.
const { app, BrowserWindow } = require("electron");
const path = require("node:path");

app.whenReady().then(() => {
  const win = new BrowserWindow({ width: 800, height: 600, title: "fwe-hello" });
  win.loadFile(path.join(__dirname, "index.html"));
  win.webContents.on("did-finish-load", () => {
    console.log("fwe-hello: page loaded");
    if (process.env.FWE_QUIT_LOADED) app.quit();
  });
});

app.on("window-all-closed", () => app.quit());
