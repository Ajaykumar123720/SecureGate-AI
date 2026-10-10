
import { db } from '../db';
import {
  VulnerabilityRecord,
  ScanRecord,
  ContainerImageRecord
} from '../data/seed';
import { spawn } from 'child_process';
import crypto from 'crypto';

type AllowedPackageType = VulnerabilityRecord['pkgType'];

type TrivyFinding = {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
  PkgType?: string;
  PublishedDate?: string;
  CVSS?: Record<
    string,
    {
      V3Score?: number;
      V2Score?: number;
      V3Vector?: string;
    }
  >;
};

type TrivyResult = {
  Target?: string;
  Type?: string;
  Vulnerabilities?: TrivyFinding[] | null;
};

type TrivyReport = {
  SchemaVersion?: number;
  Results?: TrivyResult[] | null;
};

export class ScannerService {
  private static runTrivy(args: string[]): Promise<string> {
    return new Promise((resolve, reject) => {
      const executable = process.env.TRIVY_BIN_PATH || 'trivy';

      const child = spawn(executable, args, {
        windowsHide: true,
        shell: false
      });

      let stdout = '';
      let stderr = '';
      let settled = false;

      child.stdout.on('data', (chunk: Buffer | string) => {
        stdout += chunk.toString();
      });

      child.stderr.on('data', (chunk: Buffer | string) => {
        stderr += chunk.toString();
      });

      child.on('error', (error) => {
        if (settled) return;
        settled = true;

        reject(
          new Error(
            `Unable to start Trivy. Check PATH or TRIVY_BIN_PATH. ${error.message}`
          )
        );
      });

      child.on('close', (code) => {
        if (settled) return;
        settled = true;

        if (code !== 0) {
          reject(
            new Error(
              `Trivy exited with code ${code}. ${stderr.slice(-4000)}`
            )
          );
          return;
        }

        resolve(stdout);
      });
    });
  }

  private static async getTrivyVersion(): Promise<string> {
    const output = await this.runTrivy(['--version']);
    const match = output.match(/Version:\s*([^\s]+)/i);

    if (!match) {
      throw new Error(
        'Trivy started, but its version could not be identified.'
      );
    }

    return match[1];
  }

  private static normalizePackageType(
    packageType?: string
  ): AllowedPackageType {
    const normalized = (packageType || '').toLowerCase();

    const allowedTypes: AllowedPackageType[] = [
      'golang',
      'maven',
      'npm',
      'os',
      'pip'
    ];

    return allowedTypes.includes(normalized as AllowedPackageType)
      ? (normalized as AllowedPackageType)
      : 'os';
  }

  static async initiateScan(
    imageName: string,
    imageTag: string,
    policyId?: string,
    triggeredBy = 'admin'
  ): Promise<ScanRecord> {
    if (
      !imageName?.trim() ||
      !imageTag?.trim() ||
      /[\r\n]/.test(imageName) ||
      /[\r\n]/.test(imageTag)
    ) {
      throw new Error('A valid container image name and tag are required.');
    }

    const normalizedImageName = imageName.trim();
    const normalizedImageTag = imageTag.trim();

    const trivyVersion = await this.getTrivyVersion();
    db.integrations.trivyInstalled = true;

    const policy =
      db.policies.find((p) => p.id === policyId) ||
      db.policies.find((p) => p.isDefault) ||
      db.policies[0];

    if (!policy) {
      throw new Error('No security policy is configured.');
    }

    const fullImageName =
      `${normalizedImageName}:${normalizedImageTag}`;

    let image = db.images.find(
      (img) =>
        img.name === normalizedImageName &&
        img.tag === normalizedImageTag
    );

    if (!image) {
      image = {
        id: `img-${Date.now()}`,
        name: normalizedImageName,
        tag: normalizedImageTag,
        registryId: 'reg-02',
        registryUrl: fullImageName,
        digest:
          'sha256:' +
          crypto
            .createHash('sha256')
            .update(`${fullImageName}:${Date.now()}`)
            .digest('hex'),
        sizeBytes: 0,
        os: 'Unknown until scanned',
        architecture: 'unknown',
        pushedAt: new Date().toISOString(),
        lastScannedAt: null,
        gateStatus: 'SCANNING',
        isPromotedToRelease: false,
        quarantine: true,
        activeDeployments: []
      };

      db.images.unshift(image);
    } else {
      image.gateStatus = 'SCANNING';
      image.quarantine = true;
      image.isPromotedToRelease = false;
    }

    const scan: ScanRecord = {
      id: `scan-${Date.now()}`,
      imageId: image.id,
      imageName: image.name,
      imageTag: image.tag,
      imageDigest: image.digest,

      // Match the existing ScanRecord union type.
      scannerEngine: 'Trivy Scanner Adapter v0.58.1',
      scannerVersion: trivyVersion,

      status: 'SCANNING',
      currentStage: 'Preparing Trivy vulnerability scan',
      progressPercent: 10,
      startedAt: new Date().toISOString(),
      completedAt: null,
      durationMs: null,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      gateDecision: 'EVALUATING',
      gateReason: 'Waiting for actual Trivy results.',
      policyId: policy.id,
      policyName: policy.name,
      vulnerabilities: [],
      triggeredBy
    };

    db.scans.unshift(scan);

    // Start the scan asynchronously.
    void this.runScanJob(scan, image, policy);

    db.logAudit(
      triggeredBy,
      'USER',
      'SCAN_TRIGGERED',
      'CONTAINER_IMAGE',
      fullImageName,
      'SUCCESS',
      `Trivy ${trivyVersion} vulnerability scan started for ${fullImageName}`
    );

    return scan;
  }

  private static async runScanJob(
    scan: ScanRecord,
    image: ContainerImageRecord,
    policy: (typeof db.policies)[number]
  ): Promise<void> {
    const started = Date.now();

    try {
      scan.currentStage = 'Downloading image and analyzing packages';
      scan.progressPercent = 25;

      const raw = await this.runTrivy([
        'image',
        '--scanners',
        'vuln',
        '--format',
        'json',
        '--timeout',
        '15m',
        `${image.name}:${image.tag}`
      ]);

      let report: TrivyReport;

      try {
        report = JSON.parse(raw) as TrivyReport;
      } catch {
        throw new Error(
          'Trivy returned invalid JSON. The scan cannot be approved.'
        );
      }

      // A missing or malformed report must not pass the security gate.
      if (
        !report ||
        !Array.isArray(report.Results) ||
        report.Results.length === 0
      ) {
        throw new Error(
          'Trivy returned no scan results. The image cannot be marked safe.'
        );
      }

      scan.currentStage = 'Parsing actual Trivy findings';
      scan.progressPercent = 80;

      const findings = report.Results.flatMap(
        (result) => result.Vulnerabilities ?? []
      );

      const validSeverities = [
        'CRITICAL',
        'HIGH',
        'MEDIUM',
        'LOW'
      ] as const;

      const vulnerabilities: VulnerabilityRecord[] = findings
        .filter((finding) =>
          validSeverities.includes(
            (finding.Severity || '').toUpperCase() as
              (typeof validSeverities)[number]
          )
        )
        .map((finding): VulnerabilityRecord => {
          const severity = finding.Severity!.toUpperCase() as
            | 'CRITICAL'
            | 'HIGH'
            | 'MEDIUM'
            | 'LOW';

          const cvssEntries = Object.values(finding.CVSS || {});

          const cvssScore =
            cvssEntries.find((entry) => entry.V3Score !== undefined)
              ?.V3Score ??
            cvssEntries.find((entry) => entry.V2Score !== undefined)
              ?.V2Score ??
            0;

          return {
            id: finding.VulnerabilityID || 'UNKNOWN',
            cveId: finding.VulnerabilityID || 'UNKNOWN',
            pkgName: finding.PkgName || 'unknown',
            installedVersion: finding.InstalledVersion || 'unknown',
            fixedVersion: finding.FixedVersion || null,
            severity,
            cvssScore,
            title:
              finding.Title ||
              finding.VulnerabilityID ||
              'Vulnerability',
            description: finding.Description || '',
            primaryUrl: finding.PrimaryURL || '',
            publishedDate: finding.PublishedDate || '',
            pkgType: this.normalizePackageType(finding.PkgType)
          };
        });

      const count = (severity: string) =>
        vulnerabilities.filter((v) => v.severity === severity).length;

      scan.criticalCount = count('CRITICAL');
      scan.highCount = count('HIGH');
      scan.mediumCount = count('MEDIUM');
      scan.lowCount = count('LOW');
      scan.vulnerabilities = vulnerabilities;

      // Apply the configured security policy.
      const criticalViolation =
        scan.criticalCount > policy.criticalThreshold;

      const highViolation =
        scan.highCount > policy.highThreshold;

      const mediumViolation =
        scan.mediumCount > policy.mediumThreshold;

      if (criticalViolation || highViolation || mediumViolation) {
        scan.gateDecision = 'BLOCKED';
        scan.gateReason =
          `Blocked by "${policy.name}". ` +
          `Critical: ${scan.criticalCount}/${policy.criticalThreshold}; ` +
          `High: ${scan.highCount}/${policy.highThreshold}; ` +
          `Medium: ${scan.mediumCount}/${policy.mediumThreshold}.`;
      } else {
        scan.gateDecision = 'PASSED';
        scan.gateReason =
          `Actual Trivy findings satisfy "${policy.name}". ` +
          `Critical: ${scan.criticalCount}; ` +
          `High: ${scan.highCount}; ` +
          `Medium: ${scan.mediumCount}; ` +
          `Low: ${scan.lowCount}.`;
      }

      scan.status = 'COMPLETED';
      scan.currentStage = 'Security Gate Evaluation Complete';
      scan.progressPercent = 100;
      scan.completedAt = new Date().toISOString();
      scan.durationMs = Date.now() - started;

      image.gateStatus =
        scan.gateDecision === 'PASSED' ? 'PASSED' : 'BLOCKED';

      image.lastScannedAt = scan.completedAt;

      // Cloud promotion is not implemented; keep the image quarantined.
      image.isPromotedToRelease = false;
      image.quarantine = true;

      db.logAudit(
        scan.triggeredBy,
        'SYSTEM_GATE',
        'GATE_EVALUATION',
        'CONTAINER_IMAGE',
        `${image.name}:${image.tag}`,
        scan.gateDecision === 'PASSED' ? 'SUCCESS' : 'BLOCKED',
        scan.gateReason
      );

      db.addNotification(
        `Security Gate ${scan.gateDecision}: ${image.name}:${image.tag}`,
        scan.gateReason,
        scan.gateDecision === 'PASSED' ? 'INFO' : 'CRITICAL',
        'GATE',
        `/scans/${scan.id}`
      );
    } catch (error) {
      const message =
        error instanceof Error ? error.message : String(error);

      // Fail closed: a failed scan must never be approved.
      scan.status = 'FAILED';
      scan.gateDecision = 'FAILED_SCAN';
      scan.gateReason =
        `Scan failed; image remains quarantined. ${message}`;
      scan.currentStage = 'Scan failed';
      scan.progressPercent = 100;
      scan.completedAt = new Date().toISOString();
      scan.durationMs = Date.now() - started;
      scan.vulnerabilities = [];

      scan.criticalCount = 0;
      scan.highCount = 0;
      scan.mediumCount = 0;
      scan.lowCount = 0;

      image.gateStatus = 'BLOCKED';
      image.quarantine = true;
      image.isPromotedToRelease = false;
      image.lastScannedAt = scan.completedAt;

      db.logAudit(
        scan.triggeredBy,
        'SYSTEM_GATE',
        'SCAN_FAILED',
        'CONTAINER_IMAGE',
        `${image.name}:${image.tag}`,
        'BLOCKED',
        scan.gateReason
      );

      db.addNotification(
        `Trivy Scan Failed: ${image.name}:${image.tag}`,
        scan.gateReason,
        'CRITICAL',
        'GATE',
        `/scans/${scan.id}`
      );
    }
  }
}
