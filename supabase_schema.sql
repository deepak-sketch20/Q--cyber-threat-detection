-- ==============================================================================
-- Supabase PostgreSQL Schema for Quantum Digital Signature Security Analyzer
-- Table: security_analyses
-- ==============================================================================

-- 1. Create the security_analyses table
CREATE TABLE IF NOT EXISTS public.security_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id TEXT UNIQUE,
    file_name TEXT NOT NULL,
    file_size BIGINT DEFAULT 0,
    file_type TEXT DEFAULT 'UNKNOWN',
    file_hash_sha256 TEXT NOT NULL,
    threat_score INTEGER DEFAULT 0,
    threats_detected JSONB DEFAULT '[]'::jsonb,
    signature_status TEXT DEFAULT 'UNKNOWN',
    attack_type TEXT DEFAULT 'None',
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    storage_path TEXT,
    analysis_summary JSONB,
    verification_status TEXT DEFAULT 'UNVERIFIED',
    user_id TEXT DEFAULT 'usr-01',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Performance indexes
CREATE INDEX IF NOT EXISTS idx_security_analyses_timestamp ON public.security_analyses(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_analyses_sha256 ON public.security_analyses(file_hash_sha256);
CREATE INDEX IF NOT EXISTS idx_security_analyses_threat_score ON public.security_analyses(threat_score);

-- 3. Replay Protection Table in Supabase
CREATE TABLE IF NOT EXISTS public.seen_replay_records (
    id BIGSERIAL PRIMARY KEY,
    record_type TEXT NOT NULL,
    record_value TEXT UNIQUE NOT NULL,
    signer_id TEXT,
    message_hash TEXT,
    file_name TEXT,
    first_seen DOUBLE PRECISION,
    last_seen DOUBLE PRECISION,
    hit_count INTEGER DEFAULT 1,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_replay_rec_val ON public.seen_replay_records(record_value);

-- 4. Enable Row Level Security (RLS)
ALTER TABLE public.security_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.seen_replay_records ENABLE ROW LEVEL SECURITY;

-- 5. Policies for Service Role and Anon
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies 
        WHERE tablename = 'security_analyses' AND policyname = 'Allow service role full access'
    ) THEN
        CREATE POLICY "Allow service role full access" ON public.security_analyses
            FOR ALL TO service_role USING (true) WITH CHECK (true);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies 
        WHERE tablename = 'security_analyses' AND policyname = 'Allow anon select access'
    ) THEN
        CREATE POLICY "Allow anon select access" ON public.security_analyses
            FOR SELECT TO anon, authenticated USING (true);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies 
        WHERE tablename = 'seen_replay_records' AND policyname = 'Allow service role full access replay'
    ) THEN
        CREATE POLICY "Allow service role full access replay" ON public.seen_replay_records
            FOR ALL TO service_role USING (true) WITH CHECK (true);
    END IF;
END $$;

-- 6. Storage Bucket setup for qsecure-files (50MB file size limit for free tier compliance)
INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('qsecure-files', 'qsecure-files', false, 52428800)
ON CONFLICT (id) DO NOTHING;

-- Storage policies
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies 
        WHERE tablename = 'objects' AND schemaname = 'storage' AND policyname = 'Service role full storage access'
    ) THEN
        CREATE POLICY "Service role full storage access" ON storage.objects
            FOR ALL TO service_role USING (bucket_id = 'qsecure-files') WITH CHECK (bucket_id = 'qsecure-files');
    END IF;
END $$;
