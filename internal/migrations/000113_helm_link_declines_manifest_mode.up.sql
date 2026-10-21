-- BACKLOG.md F30's manifest-mode extension.
--
-- migration 000104 built helm_link_declines for exactly one identity shape:
-- a Helm release (release_name + namespace). F30's owner decision 2026-09-09
-- widened the whole feature to also cover a plain-manifest object — no Helm
-- release, no Argo/Flux controller, matched by rendering the same way a
-- Helm release is, never by an operator-typed label selector — and that
-- case needs a decline recorded too, on the SAME table: "there is already a
-- helm_link_declines table — reuse it rather than adding a parallel notion
-- of 'the operator said no'."
--
-- A plain-manifest object has no release identity at all, so release_name/
-- namespace become nullable, and object_gvk/object_namespace/object_name
-- take their place for that mode. The CHECK constraint mirrors
-- scm.ObjectMapping.Validate's own "exactly one form, never both, never
-- neither" discipline for a CONFIRMED link — a decline's identity should be
-- no looser than a confirmation's.
ALTER TABLE helm_link_declines ALTER COLUMN release_name DROP NOT NULL;
ALTER TABLE helm_link_declines ALTER COLUMN namespace DROP NOT NULL;
ALTER TABLE helm_link_declines ADD COLUMN object_gvk text;
ALTER TABLE helm_link_declines ADD COLUMN object_namespace text;
ALTER TABLE helm_link_declines ADD COLUMN object_name text;

ALTER TABLE helm_link_declines ADD CONSTRAINT helm_link_declines_exactly_one_form CHECK (
  (release_name IS NOT NULL AND namespace IS NOT NULL
     AND object_gvk IS NULL AND object_namespace IS NULL AND object_name IS NULL)
  OR
  (release_name IS NULL AND namespace IS NULL
     AND object_gvk IS NOT NULL AND object_namespace IS NOT NULL AND object_name IS NOT NULL)
);

-- The original `UNIQUE (cluster_id, release_name, namespace)` table
-- constraint from 000104 is untouched and keeps deduplicating Helm-mode
-- rows (NULL release_name/namespace never conflict under it, which is
-- exactly why manifest-mode rows need their own index rather than relying
-- on that constraint to do double duty).
CREATE UNIQUE INDEX helm_link_declines_manifest_lookup_idx
  ON helm_link_declines (cluster_id, object_gvk, object_namespace, object_name)
  WHERE object_gvk IS NOT NULL;
