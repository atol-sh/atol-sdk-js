import { spawnSync } from 'node:child_process'
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { describe, expect, it } from 'vitest'

const PACKAGE_NAME = '@atol-sh/js'
const PACKAGE_VERSION = '1.2.3'
const EXPECTED_TARBALL = 'atol-sh-js-1.2.3.tgz'
const EXPECTED_INTEGRITY = `sha512-${Buffer.alloc(64, 7).toString('base64')}`
const RELEASE_NPM_ARCHIVE =
  'https://registry.npmjs.org/npm/-/npm-11.18.0.tgz'
const RELEASE_NPM_INTEGRITY =
  'sha512-T67M4L5wNm0cZ7EBLErcEkY1SmzEW/WJ+SADBzsFUY1UdAPfFHXFQtZ6SEXiK0+vzXysCvAsepbMaBTwnrAD+w=='

interface PackFile {
  mode: number
  path: string
  size: number
}

interface PackEntry {
  bundled: string[]
  entryCount: number
  filename: string
  files: PackFile[]
  id: string
  integrity: string
  name: string
  version: string
}

type PackReport = PackEntry[]

const readWorkflow = () =>
  readFile(resolve(process.cwd(), '.github/workflows/release.yml'), 'utf8')
const readCIWorkflow = () =>
  readFile(resolve(process.cwd(), '.github/workflows/ci.yml'), 'utf8')

const validManifest = () => ({
  name: PACKAGE_NAME,
  publishConfig: { access: 'public' },
  version: PACKAGE_VERSION,
})

const validReport = (): PackReport => [
  {
    bundled: [],
    entryCount: 2,
    filename: EXPECTED_TARBALL,
    files: [
      { mode: 0o644, path: 'index.js', size: 10 },
      { mode: 0o644, path: 'package.json', size: 100 },
    ],
    id: `${PACKAGE_NAME}@${PACKAGE_VERSION}`,
    integrity: EXPECTED_INTEGRITY,
    name: PACKAGE_NAME,
    version: PACKAGE_VERSION,
  },
]

const changedReport = (change: (entry: PackEntry) => void): PackReport => {
  const report = validReport()
  change(report[0]!)
  return report
}

const extractNpmBootstrap = (job: string) => {
  const marker = '      - name: Bootstrap verified npm CLI\n'
  const start = job.indexOf(marker)
  if (start === -1) {
    throw new Error('verified npm bootstrap is missing')
  }
  const end = job.indexOf('\n\n      - name:', start + marker.length)
  if (end === -1) {
    throw new Error('verified npm bootstrap is not followed by another step')
  }
  return job.slice(start, end)
}

const extractManifestValidator = (workflow: string) => {
  const startMarker =
    `INSPECTION_JSON="$inspection_json" MANIFEST_PATH="$manifest_path" node <<'NODE'\n`
  const start = workflow.indexOf(startMarker)
  if (start === -1) {
    throw new Error('release manifest validator start marker is missing')
  }
  const bodyStart = start + startMarker.length
  const bodyEnd = workflow.indexOf('\n          NODE', bodyStart)
  if (bodyEnd === -1) {
    throw new Error('release manifest validator end marker is missing')
  }
  return workflow
    .slice(bodyStart, bodyEnd)
    .split('\n')
    .map((line) => line.replace(/^ {10}/, ''))
    .join('\n')
}

const runManifestValidator = async ({
  expectedFileCount = '2',
  expectedIntegrity = EXPECTED_INTEGRITY,
  inspection = validReport(),
  manifest = validManifest(),
}: {
  expectedFileCount?: string
  expectedIntegrity?: string
  inspection?: PackReport | string
  manifest?: unknown
} = {}) => {
  const directory = await mkdtemp(join(tmpdir(), 'atol-release-validator-'))
  try {
    const manifestPath = join(directory, 'package.json')
    await writeFile(manifestPath, JSON.stringify(manifest))
    const validator = extractManifestValidator(await readWorkflow())
    return spawnSync(process.execPath, ['--eval', validator], {
      encoding: 'utf8',
      env: {
        ...process.env,
        EXPECTED_FILE_COUNT: expectedFileCount,
        EXPECTED_INTEGRITY: expectedIntegrity,
        EXPECTED_NAME: PACKAGE_NAME,
        EXPECTED_TARBALL,
        EXPECTED_VERSION: PACKAGE_VERSION,
        INSPECTION_JSON:
          typeof inspection === 'string'
            ? inspection
            : JSON.stringify(inspection),
        MANIFEST_PATH: manifestPath,
      },
      timeout: 10_000,
    })
  } finally {
    await rm(directory, { force: true, recursive: true })
  }
}

describe('release workflow', () => {
  it('isolates publish authority and publishes only the verified tarball', async () => {
    const workflow = await readWorkflow()
    const jobs = workflow.split('\n  publish:\n')
    expect(jobs).toHaveLength(2)
    const [qualification, publisher] = jobs

    const verifyIndex = workflow.indexOf(
      'run: node "$NPM_CLI" run verify:pack',
    )
    const packIndex = workflow.indexOf(
      'node "$NPM_CLI" pack --ignore-scripts --json',
    )
    const uploadIndex = workflow.indexOf(
      'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',
    )
    const downloadIndex = workflow.indexOf(
      'actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131',
    )
    const manifestIndex = workflow.indexOf(
      'node "$NPM_CLI" pack "$TARBALL_PATH"',
    )
    const publishIndex = workflow.indexOf(
      'node "$NPM_CLI" publish "${{ steps.verify.outputs.tarball_path }}"',
    )
    const registryIndex = workflow.indexOf(
      'timeout 5s node "$NPM_CLI" view',
    )

    expect(verifyIndex).toBeGreaterThan(-1)
    expect(packIndex).toBeGreaterThan(verifyIndex)
    expect(uploadIndex).toBeGreaterThan(packIndex)
    expect(downloadIndex).toBeGreaterThan(uploadIndex)
    expect(manifestIndex).toBeGreaterThan(downloadIndex)
    expect(publishIndex).toBeGreaterThan(manifestIndex)
    expect(registryIndex).toBeGreaterThan(publishIndex)
    expect(qualification).toContain('node "$NPM_CLI" ci --ignore-scripts')
    expect(qualification).toContain('node "$NPM_CLI" run typecheck')
    expect(qualification).toContain('node "$NPM_CLI" test')
    expect(qualification).toContain('node "$NPM_CLI" run build')
    expect(qualification).toContain('node "$NPM_CLI" run verify:pack')
    expect(qualification).not.toContain('id-token: write')
    expect(qualification).not.toContain('cache: npm')
    expect(publisher).toContain('needs: qualify')
    expect(publisher).toContain('id-token: write')
    expect(publisher).not.toContain('actions/checkout@')
    expect(publisher).not.toContain('npm ci')
    expect(publisher).not.toContain('npm install --global')
    expect(publisher).not.toContain('npm publish --dry-run')
    expect(workflow.match(/id-token: write/g)).toHaveLength(1)
    expect(workflow).not.toContain('npm install')
    expect(extractNpmBootstrap(qualification)).toBe(
      extractNpmBootstrap(publisher),
    )
    for (const job of [qualification, publisher]) {
      expect(job).toContain(`NPM_ARCHIVE_URL: "${RELEASE_NPM_ARCHIVE}"`)
      expect(job).toContain(
        `NPM_ARCHIVE_INTEGRITY: "${RELEASE_NPM_INTEGRITY}"`,
      )
      expect(job).toContain('NPM_VERSION: "11.18.0"')
      expect(job).toContain("--proto-redir '=https'")
      expect(job).toContain('actualIntegrity !== expectedIntegrity')
      expect(job).toContain(
        'test "$(node "$npm_cli" --version)" = "$NPM_VERSION"',
      )
    }
    expect(publisher).toContain(
      'node "$NPM_CLI" pack "$TARBALL_PATH" \\\n              --dry-run --ignore-scripts --json',
    )
    expect(publisher).toContain(
      'node "$NPM_CLI" publish "${{ steps.verify.outputs.tarball_path }}"',
    )
    expect(publisher).toContain('timeout 5s node "$NPM_CLI" view')
    expect(publisher).toContain(
      '--registry=https://registry.npmjs.org/ --tag=latest',
    )
    expect(workflow).toContain(
      'file_count: ${{ steps.pack.outputs.file_count }}',
    )
    expect(workflow).toContain(
      'EXPECTED_FILE_COUNT: ${{ needs.qualify.outputs.file_count }}',
    )
    expect(workflow).toContain('entry.entryCount !== expectedFileCount')
    expect(workflow).toContain('entry.integrity !== expectedIntegrity')
    expect(workflow).toContain('actualIntegrity !== expectedIntegrity')
    expect(workflow).toContain(`expectedName !== "${PACKAGE_NAME}"`)
    expect(workflow).toContain('expectedVersion !== tagVersion')
    expect(workflow).toContain('entry.id !== `${expectedName}@${expectedVersion}`')
    expect(workflow).toContain(
      'entry.files.filter((file) => file.path === "package.json").length !== 1',
    )
    expect(workflow).toContain('entry.bundled.length !== 0')
    expect(workflow).toContain('Object.keys(publishConfig).length !== 1')
    expect(workflow).toContain('publishConfig.access !== "public"')
    expect(workflow).toContain(
      'entries.length !== 1 || entries[0] !== filename',
    )
    expect(workflow).toContain('for attempt in $(seq 1 12)')
    expect(workflow).toContain('sleep 5')
    expect(workflow).toContain(
      'registry_integrity" != "$EXPECTED_INTEGRITY',
    )
    expect(workflow).toContain(
      'actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0',
    )
    expect(workflow).toContain(
      'actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38',
    )
    expect(workflow).toContain(
      'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',
    )
    expect(workflow).toContain(
      'actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131',
    )
    expect(workflow.match(/node-version: "22\.23\.1"/g)).toHaveLength(2)
    expect(workflow).not.toMatch(/uses:\s+[^@\s]+@v\d+\b/)
  })

  it('accepts the exact qualified npm pack report and manifest', async () => {
    const result = await runManifestValidator()
    expect(result.status, result.stderr).toBe(0)
  })

  it('does not execute package lifecycle scripts during tarball inspection', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'atol-release-scripts-'))
    try {
      const packageDirectory = join(directory, 'package')
      const archive = join(directory, EXPECTED_TARBALL)
      const sentinel = join(directory, 'lifecycle-ran')
      await mkdir(packageDirectory)
      await writeFile(
        join(packageDirectory, 'package.json'),
        JSON.stringify({
          name: PACKAGE_NAME,
          publishConfig: { access: 'public' },
          scripts: {
            postpack: 'node sentinel.cjs',
            prepack: 'node sentinel.cjs',
            prepare: 'node sentinel.cjs',
            prepublishOnly: 'node sentinel.cjs',
          },
          version: PACKAGE_VERSION,
        }),
      )
      await writeFile(
        join(packageDirectory, 'sentinel.cjs'),
        `require('node:fs').writeFileSync(${JSON.stringify(sentinel)}, 'ran')\n`,
      )
      const packed = spawnSync(
        'tar',
        ['-czf', archive, '-C', directory, 'package'],
        {
          encoding: 'utf8',
          env: { ...process.env, COPYFILE_DISABLE: '1' },
          timeout: 10_000,
        },
      )
      expect(packed.status, packed.stderr).toBe(0)

      const inspected = spawnSync(
        'npm',
        ['pack', archive, '--dry-run', '--ignore-scripts', '--json'],
        { cwd: directory, encoding: 'utf8', timeout: 30_000 },
      )
      expect(inspected.status, inspected.stderr).toBe(0)
      expect(JSON.parse(inspected.stdout)).toHaveLength(1)
      await expect(access(sentinel)).rejects.toThrow()
    } finally {
      await rm(directory, { force: true, recursive: true })
    }
  })

  it('rejects a mismatched internal package manifest', async () => {
    for (const manifest of [
      { ...validManifest(), name: '@substituted/package' },
      { ...validManifest(), version: '9.9.9' },
    ]) {
      const result = await runManifestValidator({ manifest })
      expect(result.status, result.stderr).not.toBe(0)
    }
  })

  it('rejects duplicate package.json entries', async () => {
    const inspection = changedReport((entry) => {
      entry.files.push({ mode: 0o644, path: 'package.json', size: 100 })
      entry.entryCount = entry.files.length
    })
    const result = await runManifestValidator({
      expectedFileCount: '3',
      inspection,
    })
    expect(result.status, result.stderr).not.toBe(0)
  })

  it('rejects bundled dependencies', async () => {
    const inspection = changedReport((entry) => {
      entry.bundled = ['substituted-dependency']
    })
    const result = await runManifestValidator({ inspection })
    expect(result.status, result.stderr).not.toBe(0)
  })

  it('rejects malformed npm pack JSON', async () => {
    const result = await runManifestValidator({ inspection: '{not-json' })
    expect(result.status, result.stderr).not.toBe(0)
  })

  it('rejects a digest mismatch', async () => {
    const inspection = changedReport((entry) => {
      entry.integrity = `sha512-${Buffer.alloc(64, 8).toString('base64')}`
    })
    const result = await runManifestValidator({ inspection })
    expect(result.status, result.stderr).not.toBe(0)
  })

  it('rejects a qualified file-count mismatch', async () => {
    const result = await runManifestValidator({ expectedFileCount: '3' })
    expect(result.status, result.stderr).not.toBe(0)
  })

  it('rejects package report name, version, and id substitutions', async () => {
    const inspections = [
      changedReport((entry) => {
        entry.name = '@substituted/package'
      }),
      changedReport((entry) => {
        entry.version = '9.9.9'
      }),
      changedReport((entry) => {
        entry.id = '@substituted/package@9.9.9'
      }),
    ]
    for (const inspection of inspections) {
      const result = await runManifestValidator({ inspection })
      expect(result.status, result.stderr).not.toBe(0)
    }
  })

  it('rejects publishConfig substitutions', async () => {
    const manifests = [
      {
        ...validManifest(),
        publishConfig: {
          access: 'public',
          registry: 'https://registry.example.invalid/',
        },
      },
      { ...validManifest(), publishConfig: { access: 'restricted' } },
    ]
    for (const manifest of manifests) {
      const result = await runManifestValidator({ manifest })
      expect(result.status, result.stderr).not.toBe(0)
    }
  })

  it('pins every action in the downstream CI artifact path', async () => {
    const workflow = await readCIWorkflow()

    expect(workflow).toContain(
      'actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0',
    )
    expect(workflow).toContain(
      'actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38',
    )
    expect(workflow).toContain(
      'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',
    )
    expect(workflow).toContain('node-version: "22.23.1"')
    expect(workflow).toContain(
      'npm install --global --ignore-scripts --no-audit --no-fund npm@11.18.0',
    )
    expect(workflow).not.toMatch(/uses:\s+[^@\s]+@v\d+\b/)
  })
})
