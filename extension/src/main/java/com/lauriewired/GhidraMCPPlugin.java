package com.lauriewired;

import java.io.IOException;

import com.lauriewired.ghidramcp.gui.GuiProgramProvider;
import com.lauriewired.ghidramcp.gui.InstanceRegistry;
import com.lauriewired.ghidramcp.http.BackendHttpServer;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ghidra.app.DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "GhidraMCP backend",
	description = "Serves the current program to the ghidra-mcp MCP server over a loopback-only " +
		"HTTP backend. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

	private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
	private static final String PORT_OPTION_NAME = "Server Port";
	private static final int DEFAULT_PORT = 8080;

	private BackendHttpServer backend;
	private InstanceRegistry registry;

	public GhidraMCPPlugin(PluginTool tool) {
		super(tool);
		tool.getOptions(OPTION_CATEGORY_NAME).registerOption(PORT_OPTION_NAME, DEFAULT_PORT, null,
			"The loopback port the GhidraMCP backend listens on. Requires Ghidra restart or " +
				"plugin reload to take effect after changing.");
	}

	@Override
	protected void init() {
		super.init();
		Options options = tool.getOptions(OPTION_CATEGORY_NAME);
		int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
		backend = new BackendHttpServer(new GuiProgramProvider(tool));
		try {
			backend.start(port);
		}
		catch (IOException e) {
			// Usually another CodeBrowser window already holds the configured port. Take a free
			// one instead; ghidra-mcp finds it through the instance registry.
			try {
				backend.start(0);
				Msg.info(this, "Port " + port + " is in use; this CodeBrowser's GhidraMCP backend " +
					"uses 127.0.0.1:" + backend.getPort() + " instead.");
			}
			catch (IOException e2) {
				Msg.error(this, "Could not start the GhidraMCP backend on 127.0.0.1:" + port +
					" or on a free port.", e2);
				return;
			}
		}
		registry = InstanceRegistry.register(backend.getPort());
	}

	@Override
	protected void dispose() {
		if (registry != null) {
			registry.unregister();
			registry = null;
		}
		if (backend != null) {
			backend.stop();
			backend = null;
		}
		super.dispose();
	}
}
