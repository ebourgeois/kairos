package uki

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kairos-io/kairos/v4/agent/pkg/action"
	"github.com/kairos-io/kairos/v4/agent/pkg/constants"
	"github.com/kairos-io/kairos/v4/agent/pkg/elemental"
	v1 "github.com/kairos-io/kairos/v4/agent/pkg/implementations/spec"
	elementalUtils "github.com/kairos-io/kairos/v4/agent/pkg/utils"
	events "github.com/kairos-io/kairos/v4/sdk/bus"
	"github.com/kairos-io/kairos/v4/sdk/signatures"
	sdkConfig "github.com/kairos-io/kairos/v4/sdk/types/config"
	"github.com/kairos-io/kairos/v4/sdk/utils"
)

type UpgradeAction struct {
	cfg  *sdkConfig.Config
	spec *v1.UpgradeUkiSpec
}

func NewUpgradeAction(cfg *sdkConfig.Config, spec *v1.UpgradeUkiSpec) *UpgradeAction {
	return &UpgradeAction{cfg: cfg, spec: spec}
}

func (i *UpgradeAction) Run() (err error) {
	e := elemental.NewElemental(i.cfg)
	cleanup := utils.NewCleanStack()
	defer func() { err = cleanup.Cleanup(err) }()
	// Run pre-install stage
	if err = elementalUtils.RunStage(i.cfg, "kairos-uki-upgrade.pre"); err != nil {
		i.cfg.Logger.Errorf("running kairos-uki-upgrade.pre stage: %s", err.Error())
	}

	if err = events.RunHookScript("/usr/bin/kairos-agent.uki.upgrade.pre.hook"); err != nil {
		i.cfg.Logger.Errorf("running kairos-uki-upgrade.pre hook script: %s", err.Error())
	}

	// REMOUNT /efi as RW (its RO by default)
	umount, err := e.MountRWPartition(i.spec.EfiPartition)
	if err != nil {
		i.cfg.Logger.Errorf("remounting efi as RW: %s", err.Error())
		return err
	}
	cleanup.Push(umount)

	// We copy first and then rotate, so the sizes that matter are only known
	// once the new set is on disk. The check runs after the dump below and
	// before the rotation, in checkSpaceForUpgradeRotation.

	// When upgrading recovery or single entries, we don't want to replace loader.conf or any other
	// files, thus we take a simpler approach and only install the new efi file
	// and the relevant conf
	if i.spec.RecoveryUpgrade() {
		i.cfg.Logger.Infof("installing entry: recovery")
		return i.installRecovery()
	}

	if i.spec.Entry != "" { // single entry upgrade
		i.cfg.Logger.Infof("installing entry: %s", i.spec.Entry)
		return i.installEntry(i.spec.Entry)
	}

	i.cfg.Logger.Infof("installing entry: active")
	// Dump artifact to efi dir
	_, err = e.DumpSource(constants.UkiEfiDir, i.spec.Active.Source)
	if err != nil {
		i.cfg.Logger.Errorf("dumping the source: %s", err.Error())
		return err
	}

	// Check if the upgrade artifact contains the proper signature before copying
	err = signatures.CheckArtifactSignatureIsValid(i.cfg.Fs, filepath.Join(constants.UkiEfiDir, "EFI", "Kairos", fmt.Sprintf("%s.efi", UnassignedArtifactRole)), i.cfg.Logger)
	if err != nil {
		i.cfg.Logger.Logger.Error().Err(err).Msg("Checking signature before upgrading")
		// Remove efi file to not occupy space and leave stuff around
		cleanup.Push(func() error {
			return removeArtifactSetWithRole(i.cfg.Fs, constants.UkiEfiDir, UnassignedArtifactRole)
		})
		i.cfg.Logger.Logger.Warn().Msg("Upgrade artifact signature does not match, upgrading to this source would result in an unbootable active system.\n" +
			"Check the upgrade source and confirm that its signed with a valid key, that key is in the machine DB and it has not been blacklisted.")
		return err
	}

	// The rotation deletes passive and then active before it writes anything in
	// their place, so a copy that runs out of room part way leaves nothing to
	// boot. Check that both copies fit while both sets are still on disk.
	if err = checkSpaceForUpgradeRotation(i.cfg.Fs, constants.UkiEfiDir, i.cfg.Logger); err != nil {
		i.cfg.Logger.Errorf("checking space on the EFI partition: %s", err.Error())
		// Drop the set we just dumped, it is no use to anyone now
		cleanup.Push(func() error {
			return removeArtifactSetWithRole(i.cfg.Fs, constants.UkiEfiDir, UnassignedArtifactRole)
		})
		return err
	}

	// Rotate first
	err = overwriteArtifactSetRole(i.cfg.Fs, constants.UkiEfiDir, "active", "passive", i.cfg.Logger)
	if err != nil {
		i.cfg.Logger.Errorf("rotating active to passive: %s", err.Error())
		return fmt.Errorf("rotating active to passive: %w", err)
	}

	// Install the new artifacts as "active"
	err = overwriteArtifactSetRole(i.cfg.Fs, constants.UkiEfiDir, UnassignedArtifactRole, "active", i.cfg.Logger)
	if err != nil {
		i.cfg.Logger.Errorf("installing the new artifacts as active: %s", err.Error())
		return fmt.Errorf("installing the new artifacts as active: %w", err)
	}

	if err = removeArtifactSetWithRole(i.cfg.Fs, constants.UkiEfiDir, UnassignedArtifactRole); err != nil {
		i.cfg.Logger.Errorf("removing artifact set: %s", err.Error())
		return fmt.Errorf("removing artifact set: %w", err)
	}

	// The rest (sort key, boot assessment, default boot entry, loader.conf
	// key cleanup, EFI key upgrades, kairos-uki-upgrade.after stage/hook)
	// is finalize work whose on-disk formats the target image owns. Same
	// argument as the non-UKI path in agent/pkg/action/upgrade.go: to keep
	// a format change from needing every previously released host agent
	// to already understand it, we hand off to the target's own
	// kairos-agent -- extracted here from the .initrd of the now-active
	// signed .efi -- and fall back to running the same finalize inline
	// when the target predates the handoff.
	return i.runFinalizeStep()
}

// runFinalizeStep hands the UKI finalize step off to the target image's
// kairos-agent, extracted from the .initrd section of the now-active
// signed .efi, and falls back to running the same finalize inline for
// targets that predate the upgrade-finalize subcommand. Preserves the
// order the rest of Run() relied on: the caller has already dumped, ver-
// ified, and rotated the artifacts.
//
// Fallback contract, mirroring the non-UKI runFinalizeStep in
// agent/pkg/action/upgrade.go: only the setup phase (temp dir, .initrd
// extract, marker + binary presence) is allowed to fall back to the
// inline path. Every one of those branches runs BEFORE the extracted
// target agent has been exec'd, so none of them has written anything to
// the ESP yet — an inline retry is safe. Once the target agent is
// exec'd its exit code is propagated (see the Runner.Run below) and NOT
// retried inline, for the same reason the non-UKI side documents: if
// the target decided the upgrade cannot proceed, honoring that decision
// matters more than papering over it with a possibly-buggier older code
// path, and by then the target may have already rewritten loader.conf
// keys / boot assessment / sort keys where an inline retry would
// double-write.
func (i *UpgradeAction) runFinalizeStep() error {
	ctx := i.buildFinalizeContext()
	activeEfi := filepath.Join(constants.UkiEfiDir, "EFI", "Kairos", "active.efi")

	tempDir, err := os.MkdirTemp("", "kairos-uki-finalize-*")
	if err != nil {
		i.cfg.Logger.Warnf("could not create temp dir for target agent extraction: %s; running finalize inline", err)
		return RunFinalize(i.cfg, ctx)
	}
	defer os.RemoveAll(tempDir)

	// Extract the multi-call binary at /usr/bin/kairos (invoked here under
	// the "kairos-agent" name via argv[0] dispatch) and the capability
	// marker in one streaming pass over the .initrd. Both need to be
	// present for the handoff to be safe: the marker says the target's
	// upgrade-finalize subcommand exists, the binary is what will run it.
	extractedAgent := filepath.Join(tempDir, "kairos-agent")
	extractedMarker := filepath.Join(tempDir, "capability-marker")
	found, err := ExtractFromInitrd(activeEfi, map[string]string{
		"/usr/bin/kairos": extractedAgent,
		constants.UpgradeFinalizeCapabilityMarker: extractedMarker,
	})
	if err != nil {
		i.cfg.Logger.Warnf("could not read .initrd of %s: %s; running finalize inline", activeEfi, err)
		return RunFinalize(i.cfg, ctx)
	}

	hasAgent := containsPath(found, "/usr/bin/kairos")
	hasMarker := containsPath(found, constants.UpgradeFinalizeCapabilityMarker)
	if !hasAgent || !hasMarker {
		i.cfg.Logger.Info("Target image predates the upgrade-finalize subcommand, running finalize inline")
		return RunFinalize(i.cfg, ctx)
	}
	if err := os.Chmod(extractedAgent, 0o755); err != nil {
		return fmt.Errorf("chmod extracted target agent: %w", err)
	}

	ctxPath := filepath.Join(tempDir, "context.json")
	if err := action.WriteFinalizeContext(i.cfg.Fs, ctxPath, ctx); err != nil {
		return fmt.Errorf("writing finalize context: %w", err)
	}

	i.cfg.Logger.Infof("Handing off upgrade finalize to target kairos-agent (extracted from %s)", activeEfi)
	out, err := i.cfg.Runner.Run(extractedAgent, "upgrade-finalize", "--context-file", ctxPath)
	if len(out) > 0 {
		i.cfg.Logger.Infof("upgrade-finalize output: %s", string(out))
	}
	return err
}

// buildFinalizeContext packs the fields uki.RunFinalize (and the target's
// upgrade-finalize subcommand) need out of the spec into a serializable
// FinalizeContext.
func (i *UpgradeAction) buildFinalizeContext() action.FinalizeContext {
	return action.FinalizeContext{
		Mode:            action.UpgradeModeUki,
		Arch:            i.cfg.Arch,
		RecoveryUpgrade: i.spec.RecoveryUpgrade(),
		UkiEntry:        i.spec.Entry,
		EFIPartition: &action.SerializedPartition{
			Path:            i.spec.EfiPartition.Path,
			Name:            i.spec.EfiPartition.Name,
			MountPoint:      i.spec.EfiPartition.MountPoint,
			FS:              i.spec.EfiPartition.FS,
			FilesystemLabel: i.spec.EfiPartition.FilesystemLabel,
		},
	}
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

func (i *UpgradeAction) installEntry(entry string) error {
	targetEntryFile := filepath.Join(constants.UkiEfiDir, "EFI", "kairos", fmt.Sprintf("%s.efi", entry))
	if _, err := os.Stat(targetEntryFile); err != nil {
		return fmt.Errorf("could not stat target efi file for entry %s: %s", entry, err)
	}

	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		i.cfg.Logger.Errorf("creating a tmp dir: %s", err.Error())
		return fmt.Errorf("creating a tmp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Dump artifact to tmp dir
	e := elemental.NewElemental(i.cfg)
	_, err = e.DumpSource(tmpDir, i.spec.Active.Source)
	if err != nil {
		i.cfg.Logger.Errorf("dumping the source to the tmp dir: %s", err.Error())
		return err
	}

	err = copyFile(filepath.Join(tmpDir, "EFI", "kairos", UnassignedArtifactRole+".efi"), targetEntryFile)
	if err != nil {
		i.cfg.Logger.Errorf("copying efi files: %s", err.Error())
		return err
	}

	targetConfPath := filepath.Join(constants.UkiEfiDir, "loader", "entries", fmt.Sprintf("%s.conf", entry))
	err = copyFile(
		filepath.Join(tmpDir, "loader", "entries", UnassignedArtifactRole+".conf"),
		targetConfPath)
	if err != nil {
		i.cfg.Logger.Errorf("copying conf files: %s", err.Error())
		return err
	}
	err = replaceRoleInKey(targetConfPath, "efi", UnassignedArtifactRole, entry, i.cfg.Logger)
	if err != nil {
		// Maybe a newer system where we use the "uki" key instead of "efi"
		if err := replaceRoleInKey(targetConfPath, "uki", UnassignedArtifactRole, entry, i.cfg.Logger); err != nil {
			i.cfg.Logger.Errorf("replacing role in in key %s: %s", "uki", err.Error())
			return err
		}
	}

	return nil
}

// installRecovery replaces the "recovery" role efi and conf files with
// the UnassignedArtifactRole efi and loader files from dir
func (i *UpgradeAction) installRecovery() error {
	if err := i.installEntry("recovery"); err != nil {
		return err
	}

	targetConfPath := filepath.Join(constants.UkiEfiDir, "loader", "entries", "recovery.conf")
	err := replaceConfTitle(targetConfPath, "recovery")
	if err != nil {
		i.cfg.Logger.Errorf("replacing conf title: %s", err.Error())
		return err
	}

	return nil
}
