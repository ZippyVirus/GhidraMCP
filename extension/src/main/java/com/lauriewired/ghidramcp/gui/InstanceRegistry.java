package com.lauriewired.ghidramcp.gui;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Map;

import com.google.gson.Gson;

import ghidra.util.Msg;

/**
 * Advertises a running CodeBrowser backend so ghidra-mcp can find every open window. Each
 * backend writes {@code <port>.json} to the instance directory and deletes it when it stops.
 * The directory is {@code $GHIDRA_MCP_INSTANCE_DIR}, or {@code ~/.ghidra_mcp/instances}.
 */
public final class InstanceRegistry {

	private final Path file;

	private InstanceRegistry(Path file) {
		this.file = file;
	}

	public static Path directory() {
		String override = System.getenv("GHIDRA_MCP_INSTANCE_DIR");
		if (override != null && !override.isBlank()) {
			return Paths.get(override);
		}
		return Paths.get(System.getProperty("user.home"), ".ghidra_mcp", "instances");
	}

	/** Writes the instance file, or returns null (with a logged warning) if it cannot. */
	public static InstanceRegistry register(int port) {
		Path dir = directory();
		Path file = dir.resolve(port + ".json");
		Map<String, Object> entry = new LinkedHashMap<>();
		entry.put("port", port);
		entry.put("url", "http://127.0.0.1:" + port + "/");
		entry.put("pid", ProcessHandle.current().pid());
		entry.put("started", System.currentTimeMillis());
		try {
			Files.createDirectories(dir);
			Path tmp = Files.createTempFile(dir, port + "-", ".tmp");
			Files.writeString(tmp, new Gson().toJson(entry), StandardCharsets.UTF_8);
			Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
			return new InstanceRegistry(file);
		}
		catch (IOException e) {
			Msg.warn(InstanceRegistry.class, "Could not register GhidraMCP instance in " + dir, e);
			return null;
		}
	}

	public void unregister() {
		try {
			Files.deleteIfExists(file);
		}
		catch (IOException e) {
			Msg.debug(this, "Could not remove " + file, e);
		}
	}
}
