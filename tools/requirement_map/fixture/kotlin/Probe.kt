package fixture

object Probe {
    @JvmStatic external fun entry(): Int
    @JvmStatic external fun renamed(): Int
    @JvmStatic external fun gated(): Int
    @JvmStatic external fun query(): Int
    @JvmStatic internal external fun hidden(): Int
}
