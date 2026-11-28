package me.somalabs.onepass.gradle;

import java.io.File;
import java.util.List;
import javax.inject.Inject;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.FileSystemOperations;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.Internal;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.TaskAction;
import org.gradle.process.ExecOperations;

/**
 * Runs {@code uniffi-bindgen generate --library <host lib> --language kotlin}
 * through cargo (the binary of core/onepass-ffi), into {@link #getOutputDir()}.
 * The Kotlin settings come from core/onepass-ffi/uniffi.toml.
 */
public abstract class GenerateUniffiBindings extends DefaultTask {
    /** The host build of libonepass_ffi, read for its UniFFI metadata. */
    @InputFile
    @PathSensitive(PathSensitivity.NONE)
    public abstract RegularFileProperty getLibrary();

    /** core/onepass-ffi/uniffi.toml (package name of the bindings). */
    @InputFile
    @PathSensitive(PathSensitivity.NONE)
    public abstract RegularFileProperty getConfig();

    /** The cargo workspace (core/). */
    @Internal
    public abstract DirectoryProperty getCoreDir();

    /** The cargo features of the host build, so cargo does not relink it. */
    @Input
    public abstract Property<String> getFeatures();

    /** The cargo target directory of that host build. */
    @Internal
    public abstract DirectoryProperty getTargetDir();

    @OutputDirectory
    public abstract DirectoryProperty getOutputDir();

    @Inject
    protected abstract ExecOperations getExecOperations();

    @Inject
    protected abstract FileSystemOperations getFileSystemOperations();

    @TaskAction
    public void generate() {
        File out = getOutputDir().get().getAsFile();
        getFileSystemOperations().delete(spec -> spec.delete(out));
        if (!out.mkdirs()) {
            throw new IllegalStateException("cannot create " + out);
        }
        getExecOperations().exec(spec -> {
            spec.setWorkingDir(getCoreDir().get().getAsFile());
            spec.commandLine(List.of(
                    "cargo", "run", "-q", "-p", "onepass-ffi",
                    "--features", getFeatures().get(),
                    "--target-dir", getTargetDir().get().getAsFile().getAbsolutePath(),
                    "--bin", "uniffi-bindgen", "--",
                    "generate", "--library", getLibrary().get().getAsFile().getAbsolutePath(),
                    "--language", "kotlin", "--no-format",
                    "--out-dir", out.getAbsolutePath()));
        });
    }
}
