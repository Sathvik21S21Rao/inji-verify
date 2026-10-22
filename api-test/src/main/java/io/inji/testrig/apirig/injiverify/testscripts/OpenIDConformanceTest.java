package io.inji.testrig.apirig.injiverify.testscripts;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.TreeSet;

import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.testng.Assert;
import org.testng.ITest;
import org.testng.ITestResult;
import org.testng.Reporter;
import org.testng.SkipException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import io.inji.testrig.apirig.injiverify.utils.InjiVerifyConfigManager;
import io.inji.testrig.apirig.injiverify.utils.InjiVerifyUtil;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.SkipTestCaseHandler;

/**
 * Bridge (ADR-005): runs the OpenID conformance runner as a subprocess and reports one TestNG
 * test per module. The runner computes the outcome; this class only maps it (ADR-003).
 */
public class OpenIDConformanceTest extends InjiVerifyUtil implements ITest {
	private static final Logger logger = Logger.getLogger(OpenIDConformanceTest.class);
	private static final String DEFAULT_COMPONENT = "verify"; // used until a plan record names the component
	protected String testCaseName = "";

	/** Config name = stem of the plan template; also used by InjiTestRunner for the report name. */
	public static String configName() {
		return new File(ModuleIterator.template()).getName().replaceFirst("\\.[^.]*$", "");
	}

	@Override
	public String getTestName() {
		return testCaseName;
	}

	@DataProvider(name = "conformance")
	public Iterator<Object[]> modules() {
		return new ModuleIterator();
	}

	@Test(dataProvider = "conformance")
	public void test(TestCaseDTO dto, JSONObject rec) {
		testCaseName = dto.getTestCaseName();
		String outcome = rec.optString("outcome");
		String message = str(rec, "message");
		Reporter.log("run_id: " + ModuleIterator.runId + ", plan_id: " + ModuleIterator.planId + ", config_name: "
				+ ModuleIterator.configName, true);
		Reporter.log(dto.getDescription(), true);
		Reporter.log("status/result/outcome: " + str(rec, "status") + "/" + str(rec, "result") + "/" + outcome, true);
		Reporter.log("message: " + message, true);
		JSONArray fc = rec.optJSONArray("failed_conditions");
		for (int i = 0; fc != null && i < fc.length(); i++) {
			Reporter.log("failed: " + fc.getJSONObject(i).optString("condition") + ": "
					+ fc.getJSONObject(i).optString("message"), true);
		}
		JSONArray w = rec.optJSONArray("warnings");
		for (int i = 0; w != null && i < w.length(); i++) {
			Reporter.log("warning: " + w.getJSONObject(i).optString("condition"), true);
		}
		String logUrl = str(rec, "log_url");
		Reporter.log("log_url: " + logUrl, true);
		JSONArray ev = rec.optJSONArray("evidence");
		for (int i = 0; ev != null && i < ev.length(); i++) {
			Reporter.log("evidence: " + ev.getString(i), true);
		}

		boolean ki = SkipTestCaseHandler.isTestCaseInSkippedList(testCaseName);
		if (ki && !"fail".equals(outcome)) {
			Reporter.log("known-issue entry present but outcome=" + outcome + " (stale entry?)", true);
		}
		switch (outcome) {
		case "pass":
			return;
		case "warning":
			if ("yes".equalsIgnoreCase(InjiVerifyConfigManager.getproperty("conformance.strict").trim()))
				Assert.fail(message);
			return;
		case "review":
		case "skip":
			throw new SkipException(message);
		case "fail":
			if (ki)
				throw new SkipException(GlobalConstants.KNOWN_ISSUES + ": " + message);
			Assert.fail(message + " | " + logUrl);
			return;
		default: // infra (never KI) and anything unknown
			Assert.fail(message);
		}
	}

	@AfterMethod(alwaysRun = true)
	public void setResultTestName(ITestResult result) {
		result.setAttribute("TestCaseName", testCaseName);
	}

	private static String str(JSONObject o, String k) {
		return o.isNull(k) ? "" : o.optString(k);
	}

	/** Lazily streams runner stdout; yields one {TestCaseDTO, record} per module, synthetics at EOF. */
	static class ModuleIterator implements Iterator<Object[]> {
		static String runId = "", planId = "", configName = "";
		private final Deque<Object[]> ready = new ArrayDeque<>();
		private final List<String> planModules = new ArrayList<>();
		private final List<String> seen = new ArrayList<>();
		private final JSONObject flags = new JSONObject();
		private BufferedReader in;
		private Process proc;
		private File outDir;
		private volatile boolean timedOut;
		private boolean planSeen, eof, aborted;
		private String endError = "", startError = "", component = DEFAULT_COMPONENT;
		private int index;
		private final long timeout = parseTimeout();

		ModuleIterator() {
			runId = planId = "";
			String tpl = template();
			configName = configName();
			outDir = new File(System.getProperty("user.dir") + "/testng-report/conformance/" + configName);
			outDir.mkdirs();
			start(tpl);
		}

		private static long parseTimeout() {
			try {
				return Long.parseLong(InjiVerifyConfigManager.getproperty("conformance.runner.timeout").trim());
			} catch (NumberFormatException e) {
				return 3600;
			}
		}

		private static String template() {
			String t = InjiVerifyConfigManager.getproperty("conformance.plan.template").trim();
			if (!t.isEmpty())
				return t;
			return "plans/verify/verify-redirect-uri.json";
		}

		private void start(String tpl) {
			// ponytail: whitespace split, no quoting support; use a wrapper script if the command needs it
			List<String> cmd = new ArrayList<>(Arrays.asList(
					InjiVerifyConfigManager.getproperty("conformance.runner.command").trim().split("\\s+")));
			cmd.add(tpl);
			cmd.add("--out");
			cmd.add(outDir.getAbsolutePath());
			ProcessBuilder pb = new ProcessBuilder(cmd);
			String dir = InjiVerifyConfigManager.getproperty("conformance.runner.dir").trim();
			if (!dir.isEmpty())
				pb.directory(new File(dir));
			String base = InjiVerifyConfigManager.getproperty("injiVerifyBaseUrl").trim();
			if (!base.isEmpty())
				pb.environment().put("VERIFY_API", base.replaceAll("/+$", "") + "/v1/verify");
			pb.redirectError(new File(outDir, "runner.stderr.log"));
			try {
				proc = pb.start();
			} catch (IOException e) {
				startError = e.toString();
				eof = true;
				return;
			}
			in = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8));
			Thread dog = new Thread(() -> {
				try {
					if (!proc.waitFor(timeout, java.util.concurrent.TimeUnit.SECONDS)) {
						timedOut = true;
						proc.destroyForcibly();
					}
				} catch (InterruptedException ignored) {
					// test JVM is exiting
				}
			}, "conformance-watchdog");
			dog.setDaemon(true);
			dog.start();
		}

		private String flagText() {
			StringBuilder sb = new StringBuilder();
			for (String k : new TreeSet<>(flags.keySet())) {
				if (flags.isNull(k))
					continue;
				sb.append(sb.length() == 0 ? "" : ", ").append(k).append('=').append(aborted ? "not observed" : flags.get(k));
			}
			return sb.toString();
		}

		private Object[] item(String module, JSONObject rec) {
			TestCaseDTO dto = new TestCaseDTO();
			dto.setTestCaseName("OIDF_" + component + "_" + module);
			dto.setUniqueIdentifier(String.format("OIDF_%s_%02d", configName, ++index));
			dto.setDescription(module + " [" + configName + "] " + flagText());
			return new Object[] { dto, rec };
		}

		private JSONObject infra(String module, String reason) {
			return new JSONObject().put("type", "module").put("module", module).put("outcome", "infra")
					.put("message", "INFRA: " + reason).put("status", JSONObject.NULL)
					.put("result", JSONObject.NULL);
		}

		private void readUntilItem() {
			try {
				String line;
				while (ready.isEmpty() && (line = in.readLine()) != null) {
					JSONObject o;
					try {
						o = new JSONObject(line);
					} catch (JSONException e) {
						logger.warn("runner stdout (not JSON): " + line);
						continue;
					}
					switch (o.optString("type")) {
					case "plan":
						planSeen = true;
						runId = str(o, "run_id");
						if (!str(o, "component").isEmpty())
							component = str(o, "component");
						planId = str(o, "plan_id");
						JSONObject f = o.optJSONObject("flags");
						if (f != null)
							for (String k : f.keySet())
								flags.put(k, f.get(k));
						JSONArray m = o.optJSONArray("modules");
						for (int i = 0; m != null && i < m.length(); i++)
							planModules.add(m.getString(i));
						break;
					case "module":
						seen.add(o.optString("module"));
						ready.add(item(o.optString("module"), o));
						break;
					case "end":
						if (o.optInt("exit") == 2) {
							aborted = true;
							endError = str(o, "error");
						}
						break;
					default:
						break;
					}
				}
				if (ready.isEmpty())
					finish();
			} catch (IOException e) {
				startError = e.toString();
				finish();
			}
		}

		private void finish() {
			eof = true;
			int code = -1;
			try {
				if (proc != null) {
					proc.getInputStream().close();
					code = proc.waitFor();
				}
			} catch (Exception e) {
				// keep -1
			}
			if (!planSeen) {
				String tail = startError.isEmpty() ? stderrTail() : startError;
				ready.add(item("runner", infra("runner", "runner produced no plan record (exit " + code + "): " + tail)));
				return;
			}
			String reason = aborted ? endError
					: timedOut ? "runner timeout after " + timeout + "s"
							: "runner exited without end record (exit " + code + ")";
			for (String mod : planModules)
				if (!seen.contains(mod))
					ready.add(item(mod, infra(mod, reason)));
		}

		private String stderrTail() {
			try {
				List<String> l = Files.readAllLines(new File(outDir, "runner.stderr.log").toPath());
				return String.join(" / ", l.subList(Math.max(0, l.size() - 5), l.size()));
			} catch (IOException e) {
				return "(no stderr log)";
			}
		}

		@Override
		public boolean hasNext() {
			if (ready.isEmpty() && !eof)
				readUntilItem();
			return !ready.isEmpty();
		}

		@Override
		public Object[] next() {
			if (!hasNext())
				throw new NoSuchElementException();
			return ready.poll();
		}
	}
}
