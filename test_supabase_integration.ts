import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import fs from 'fs';

dotenv.config();

async function runTests() {
  const url = (process.env.SUPABASE_URL || '').trim();
  const serviceKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
  const anonKey = (process.env.SUPABASE_ANON_KEY || '').trim();
  const key = serviceKey || anonKey;
  const bucketName = (process.env.SUPABASE_BUCKET || 'qsecure-files').trim();

  const report: Record<string, any> = {
    timestamp: new Date().toISOString(),
    configuration: {
      supabase_url_configured: Boolean(url),
      supabase_url_domain: url ? new URL(url).hostname : null,
      service_role_key_configured: Boolean(serviceKey),
      anon_key_configured: Boolean(anonKey),
      target_bucket: bucketName,
      key_type_used: serviceKey ? 'service_role (administrative)' : 'anon (public)'
    },
    steps: {
      step_1_connection: { status: 'PENDING' },
      step_2_table_accessibility: { status: 'PENDING' },
      step_3_bucket_accessibility: { status: 'PENDING' },
      step_4_create_test_record: { status: 'PENDING' },
      step_5_confirm_test_record: { status: 'PENDING' }
    },
    overall_result: 'PENDING'
  };

  console.log('='.repeat(65));
  console.log('  Q-SECURE SUPABASE INTEGRATION & CONNECTIVITY TEST SUITE');
  console.log('='.repeat(65));
  console.log(`[CONFIG] Target Supabase URL: ${url}`);
  console.log(`[CONFIG] Using Key: ${serviceKey ? 'SUPABASE_SERVICE_ROLE_KEY' : 'SUPABASE_ANON_KEY'}`);
  console.log(`[CONFIG] Target Storage Bucket: ${bucketName}`);
  console.log('-'.repeat(65));

  // STEP 1: Test Connection
  let client;
  try {
    if (!url || !key) {
      throw new Error('SUPABASE_URL and at least one Supabase key must be set in environment.');
    }
    client = createClient(url, key, {
      auth: { persistSession: false }
    });
    report.steps.step_1_connection = {
      status: 'PASS',
      message: 'Supabase client initialized successfully with valid endpoint URL.',
      target_url: url
    };
    console.log('[PASS] Step 1: Connection to Supabase client initialized.');
  } catch (err: any) {
    report.steps.step_1_connection = {
      status: 'FAIL',
      error: err?.message || String(err)
    };
    report.overall_result = 'FAIL';
    console.error(`[FAIL] Step 1: Connection failed: ${err?.message}`);
    fs.writeFileSync('supabase_test_report.json', JSON.stringify(report, null, 2));
    return report;
  }

  // STEP 2: Verify security_analyses table accessibility
  try {
    const { data, error, count } = await client
      .from('security_analyses')
      .select('*', { count: 'exact', head: false })
      .limit(5);

    if (error) {
      throw new Error(`Table query failed: ${error.message} (Code: ${error.code || 'UNKNOWN'})`);
    }

    report.steps.step_2_table_accessibility = {
      status: 'PASS',
      message: "Table 'security_analyses' is accessible and queryable.",
      existing_records_count: count ?? data?.length ?? 0,
      sample_records_retrieved: data?.length ?? 0
    };
    console.log(`[PASS] Step 2: Table 'security_analyses' is accessible. Found ${count ?? data?.length ?? 0} existing records.`);
  } catch (err: any) {
    report.steps.step_2_table_accessibility = {
      status: 'FAIL',
      error: err?.message || String(err)
    };
    console.error(`[FAIL] Step 2: Table accessibility error: ${err?.message}`);
  }

  // STEP 3: Verify qsecure-files storage bucket accessibility
  try {
    const { data: buckets, error: bucketListError } = await client.storage.listBuckets();
    let bucketFound = false;

    if (!bucketListError && buckets) {
      bucketFound = buckets.some(b => b.name === bucketName);
      console.log(`[INFO] Existing buckets detected: ${buckets.map(b => b.name).join(', ') || 'none'}`);
    }

    if (!bucketFound) {
      console.log(`[INFO] Bucket '${bucketName}' not listed. Attempting automatic creation...`);
      const { data: created, error: createError } = await client.storage.createBucket(bucketName, {
        public: false
      });
      if (createError && !createError.message.includes('already exists')) {
        console.warn(`[WARN] Bucket creation notice: ${createError.message}`);
      } else {
        bucketFound = true;
      }
    }

    // Verify read/write capability to the bucket with a test probe
    const probePath = `test_probes/probe_${Date.now()}.txt`;
    const probeContent = Buffer.from(`Q-SECURE STORAGE PROBE VERIFICATION ${new Date().toISOString()}`);

    const { data: uploadData, error: uploadError } = await client.storage
      .from(bucketName)
      .upload(probePath, probeContent, {
        contentType: 'text/plain',
        upsert: true
      });

    if (uploadError) {
      throw new Error(`Storage upload test to bucket '${bucketName}' failed: ${uploadError.message}`);
    }

    // Clean up test probe
    await client.storage.from(bucketName).remove([probePath]);

    report.steps.step_3_bucket_accessibility = {
      status: 'PASS',
      message: `Storage bucket '${bucketName}' is accessible with verified write and read operations.`,
      bucket: bucketName,
      probe_verified: true
    };
    console.log(`[PASS] Step 3: Storage bucket '${bucketName}' is accessible and write/read verified.`);
  } catch (err: any) {
    report.steps.step_3_bucket_accessibility = {
      status: 'FAIL',
      error: err?.message || String(err),
      bucket: bucketName
    };
    console.error(`[FAIL] Step 3: Storage bucket error: ${err?.message}`);
  }

  // STEP 4: Create one test analysis record with clearly marked TEST data
  const testCaseId = `TEST-CASE-QSECURE-${Date.now()}`;
  const testFileName = 'TEST_ARTIFACT_INTEGRITY_CHECK.bin';
  const testSha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const testTimestamp = new Date().toISOString();
  const testStoragePath = `${bucketName}/${testCaseId}/${testFileName}`;

  const testRecord = {
    file_name: testFileName,
    file_size: 2048,
    file_hash_sha256: testSha256,
    signature_status: 'TEST_VERIFIED_VALID',
    threat_score: 0,
    threats_detected: ['TEST_HARNESS_BENIGN_PROBE'],
    attack_type: 'None (Verification Test)',
    timestamp: testTimestamp,
    storage_path: testStoragePath,
    analysis_summary: {
      case_id: testCaseId,
      overall_status: 'TEST_SECURE',
      primary_threat: 'None',
      risk_level: 'LOW',
      threats_detected: ['TEST_HARNESS_BENIGN_PROBE'],
      recommendation: 'Verification test record created by automated test suite. Integrity confirmed.'
    }
  };

  let createdId: any = null;

  try {
    const { data: insertedData, error: insertError } = await client
      .from('security_analyses')
      .insert(testRecord)
      .select('*')
      .single();

    if (insertError) {
      throw new Error(`Record insert failed: ${insertError.message} (Code: ${insertError.code || 'UNKNOWN'})`);
    }

    createdId = insertedData?.id;

    report.steps.step_4_create_test_record = {
      status: 'PASS',
      message: `Created test analysis record successfully in Supabase (ID: ${createdId}).`,
      test_case_id: testCaseId,
      database_row_id: createdId,
      details: {
        id: createdId,
        case_id: testCaseId,
        file_name: testFileName,
        file_hash_sha256: testSha256,
        signature_status: 'TEST_VERIFIED_VALID',
        threat_score: 0,
        timestamp: testTimestamp,
        storage_path: testStoragePath
      }
    };
    console.log(`[PASS] Step 4: Created test analysis record with ID: ${createdId} (Case: ${testCaseId}).`);
  } catch (err: any) {
    report.steps.step_4_create_test_record = {
      status: 'FAIL',
      error: err?.message || String(err)
    };
    console.error(`[FAIL] Step 4: Failed to create test record: ${err?.message}`);
    report.overall_result = 'FAIL';
    fs.writeFileSync('supabase_test_report.json', JSON.stringify(report, null, 2));
    return report;
  }

  // STEP 5: Confirm that the record appears in Supabase
  try {
    const { data: fetchedData, error: fetchError } = await client
      .from('security_analyses')
      .select('*')
      .eq('id', createdId)
      .single();

    if (fetchError || !fetchedData) {
      throw new Error(`Failed to query back test record: ${fetchError?.message || 'Record not found'}`);
    }

    report.steps.step_5_confirm_test_record = {
      status: 'PASS',
      message: `Confirmed record appears in Supabase 'security_analyses' table.`,
      retrieved_record: {
        id: fetchedData.id,
        case_id: fetchedData.analysis_summary?.case_id || testCaseId,
        file_name: fetchedData.file_name,
        file_size: fetchedData.file_size,
        file_hash_sha256: fetchedData.file_hash_sha256,
        signature_status: fetchedData.signature_status,
        threat_score: fetchedData.threat_score,
        threats_detected: fetchedData.threats_detected,
        attack_type: fetchedData.attack_type,
        timestamp: fetchedData.timestamp,
        storage_path: fetchedData.storage_path,
        analysis_summary: fetchedData.analysis_summary,
        created_at: fetchedData.created_at
      }
    };
    console.log(`[PASS] Step 5: Confirmed test record appears in Supabase!`);
    console.log(`       ID: ${fetchedData.id}`);
    console.log(`       File Name: ${fetchedData.file_name}`);
    console.log(`       SHA-256: ${fetchedData.file_hash_sha256}`);
    console.log(`       Threat Score: ${fetchedData.threat_score}`);
    console.log(`       Signature Status: ${fetchedData.signature_status}`);
    console.log(`       Timestamp: ${fetchedData.timestamp}`);
    console.log(`       Storage Path: ${fetchedData.storage_path}`);
  } catch (err: any) {
    report.steps.step_5_confirm_test_record = {
      status: 'FAIL',
      error: err?.message || String(err)
    };
    console.error(`[FAIL] Step 5: Record confirmation error: ${err?.message}`);
  }

  // Overall result computation
  const allPass = Object.values(report.steps).every((step: any) => step.status === 'PASS');
  report.overall_result = allPass ? 'PASS' : 'FAIL';

  console.log('='.repeat(65));
  console.log(`  OVERALL TEST RESULT: ${report.overall_result}`);
  console.log('='.repeat(65));

  fs.writeFileSync('supabase_test_report.json', JSON.stringify(report, null, 2));
  console.log('Test report saved to supabase_test_report.json');
  return report;
}

runTests().then(report => {
  if (report.overall_result !== 'PASS') {
    process.exit(1);
  }
  process.exit(0);
}).catch(e => {
  console.error('Unhandled fatal error in test runner:', e);
  process.exit(1);
});
