module.exports = {
    // Disable credential encryption so credentials in flows.json are used as-is.
    credentialSecret: false,

    uiPort: process.env.PORT || 1880,
    httpAdminRoot: "/",
    httpNodeRoot: "/",
    userDir: "/data",
    flowFile: "flows.json",
    editorTheme: {
        projects: {
            enabled: false,
        },
    },
};
