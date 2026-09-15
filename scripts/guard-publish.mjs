// Defense in depth only (decision Q83): refuses `npm publish` outside the protected release workflow.
if (process.env.EGO_RELEASE_WORKFLOW !== '1') {
  console.error(
    'publish refused: EGO is published only by the protected release workflow (EGO_RELEASE_WORKFLOW=1).',
  );
  process.exit(1);
}
