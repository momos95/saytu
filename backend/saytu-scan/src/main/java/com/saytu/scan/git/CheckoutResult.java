package com.saytu.scan.git;

import java.nio.file.Path;

/**
 * A checked-out branch, without its {@code .git} directory.
 *
 * @param sourceDir  working tree to analyse
 * @param commitSha  commit that was checked out
 * @param totalBytes size of the working tree
 * @param fileCount  number of regular files
 */
public record CheckoutResult(Path sourceDir, String commitSha, long totalBytes, long fileCount) {
}
