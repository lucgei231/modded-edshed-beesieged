/**
 * =============================================================================
 * FILE: 3777.7e795376.js (Webpack Chunk ID: 3777)
 * PURPOSE: Keyboard and Settings UI Components
 * CONTENT: 
 *   - Module 21843: KeyboardView - Interactive on-screen keyboard component
 *   - Module 86567: SettingsModal - Game settings/pause menu modal
 * TECHNOLOGY: Vue.js 2, Bulma CSS framework
 * =============================================================================
 */

"use strict";
(self["webpackChunkgame"] = self["webpackChunkgame"] || []).push([
  [3777],
  {
    // ====== MODULE 21843: KeyboardView Component ======
    // Renders an interactive on-screen keyboard for spelling/typing practice
    // Supports: QWERTY layout, Phonics layout, Accents, Capital letters
    // Events: keystroke, phoneme audio, selection tracking
    21843: function (e, t, s) {
      s.d(t, {
        A: function () {
          return l;
        },
      });
      var i = function () {
          var e = this,
            t = e.$createElement,
            s = e._self._c || t;
          return s(
            "div",
            {
              class: {
                accents: e.accents,
                shift: e.capitals,
                spaces: e.hasSpaces,
              },
              attrs: { id: "keyboardView" },
            },
            [
              e.hide
                ? e._e()
                : s("div", { staticClass: "keyboard-view__inner" }, [
                    s(
                      "ul",
                      {
                        class: { clear: !0, buzzwords: e.buzzwords },
                        attrs: { id: "grid" },
                      },
                      e._l(e.keys, function (t, i) {
                        return s(
                          "li",
                          {
                            key: "keyboard-key-" + i + "-" + t,
                            class: {
                              buzzwords: e.buzzwords,
                              enabled:
                                e.buzzwords &&
                                e.connected &&
                                e.canSelect(i) &&
                                !e.hexSelected(i) &&
                                e.selectedIndices.length > 0,
                              disabled:
                                e.buzzwords &&
                                e.connected &&
                                !e.canSelect(i) &&
                                !e.hexSelected(i) &&
                                e.selectedIndices.length > 0,
                              latest:
                                e.buzzwords &&
                                e.connected &&
                                e.latestSelection == i &&
                                e.hexSelected(i),
                              "is-shift": "⇪" === t,
                              "is-accents": "~" === t,
                            },
                          },
                          [
                            s(
                              "div",
                              {
                                class: {
                                  hexagon: !0,
                                  "is-selected":
                                    e.hexSelected(i) &&
                                    (!e.connected || i != e.latestSelection),
                                },
                              },
                              [
                                s(
                                  "a",
                                  {
                                    attrs: {
                                      href: "#",
                                      tabindex: "-1",
                                      draggable: "false",
                                    },
                                    on: {
                                      keydown: function (t) {
                                        if (
                                          !t.type.indexOf("key") &&
                                          e._k(
                                            t.keyCode,
                                            "enter",
                                            13,
                                            t.key,
                                            "Enter",
                                          )
                                        )
                                          return null;
                                        t.preventDefault();
                                      },
                                      click: function (t) {
                                        return (
                                          t.preventDefault(),
                                          e.didClick(i)
                                        );
                                      },
                                      mouseenter: function (t) {
                                        return e.didMouseOver(i);
                                      },
                                    },
                                  },
                                  [
                                    s("div", { staticClass: "inner" }, [
                                      s(
                                        "p",
                                        { class: { phonics: 1 == e.phonics } },
                                        [e._v(e._s(t))],
                                      ),
                                    ]),
                                  ],
                                ),
                              ],
                            ),
                          ],
                        );
                      }),
                      0,
                    ),
                  ]),
            ],
          );
        },
        n = [],
        a =
          (s(44114),
          s(18111),
          s(22489),
          s(61701),
          s(62953),
          {
            // ====== KEYBOARDVIEW COMPONENT CONFIGURATION ======
            name: "KeyboardView", // Component name: on-screen keyboard
            props: [
              "letters", // Array of letter keys to display
              "gpcs", // Grapheme-phoneme correspondences for phonetics mode
              "selectedIndices", // Track which keys are selected (for Beekeeper mode)
              "qwerty", // Boolean: true = QWERTY layout, false = phonics layout
              "active", // Is keyboard accepting input?
              "phonics", // Show phonics pronunciation?
              "beekeeper", // Beekeeper mode - hexagon selection logic
              "buzzwords", // Highlight buzzwords mode?
              "connected", // Is connected to multiplayer server?
              "capitals", // Show capital letters?
              "accents", // Show accented characters (with ~ key)?
              "hide", // Hide keyboard completely?
              "backspacePreventDefault", // Prevent default backspace behavior?
            ],
            data() {
              return {}; // No local state - all state from parent props
            },
            computed: {
              // ====== COMPUTED PROPERTIES: Derived state ======
              keys() {
                // Build key array: use GPCs if phonics mode, otherwise use letters
                return this.phonics && this.gpcs && this.gpcs.length
                  ? this.gpcs.map((e) => e.grapheme) // Phonics: extract grapheme from GPC
                  : this.letters; // QWERTY: use letters array directly
              },
              selectableIndices() {
                if (
                  !this.buzzwords ||
                  !this.connected ||
                  0 === this.selectedIndices.length
                )
                  return null;
                const e = this.selectedIndices[this.selectedIndices.length - 1],
                  t = [];
                return (
                  e % 6 !== 0 && t.push(e - 1),
                  e % 6 !== 5 && t.push(e + 1),
                  e > 5 && t.push(e - 6),
                  e < 12 && t.push(e + 6),
                  e % 6 !== 0 &&
                    (e % 2 === 0 ? t.push(e - 7) : e < 12 && t.push(e + 5)),
                  e % 6 !== 5 &&
                    (e % 2 === 0 ? t.push(e - 5) : e < 11 && t.push(e + 7)),
                  t
                );
              },
              latestSelection() {
                if (0 === this.selectedIndices.length) return null;
                const e = this.selectedIndices[this.selectedIndices.length - 1];
                return e;
              },
              hasSpaces() {
                return this.keys.includes("⎵");
              },
            },
            // ====== LIFECYCLE HOOKS ======
            created() {
              // Attach keyboard event listeners when component is created
              (window.addEventListener("keyup", this.didKeyUp),
                window.addEventListener("keydown", this.didKeyDown),
                window.addEventListener("keypress", this.didKeyDown));
            },
            destroyed() {
              // Remove keyboard event listeners when component is destroyed
              (window.removeEventListener("keyup", this.didKeyUp),
                window.removeEventListener("keydown", this.didKeyDown),
                window.removeEventListener("keypress", this.didKeyDown));
            },
            mounted() {
              // Component is attached to DOM
            },
            methods: {
              // ====== USER INTERACTION HANDLERS ======
              
              // Check if a key at index can be selected (Beekeeper hexagon logic)
              canSelect(e) {
                return !(
                  this.selectableIndices && !this.selectableIndices.includes(e)
                );
              },
              
              // Handle physical keyboard key press
              // Manages: backspace prevention, shift/capital toggle
              didKeyDown(e) {
                ((8 !== e.which && 222 !== e.which) || // Backspace (8) or quote (222)
                  !this.backspacePreventDefault ||
                  e.preventDefault(),
                  this.active && 16 === e.which && this.didShift()); // Shift (16)
              },
              
              // Handle physical keyboard key release
              // Matches character to key index and emits event
              didKeyUp(e) {
                if (this.active) {
                  let t = String.fromCharCode(e.which).toLocaleLowerCase();
                  if (189 === e.which) t = "-";
                  else if (
                    222 === e.which ||
                    192 === e.which ||
                    223 === e.which
                  )
                    t = "'";
                  else {
                    if (16 === e.which) return void this.didUnShift();
                    32 === e.which && (t = "⎵");
                  }
                  this.capitals && (t = t.toUpperCase());
                  let s = -1;
                  for (let e = 0; e < this.keys.length; e++) {
                    const i = this.keys[e];
                    if (i === t && !this.selectedIndices.includes(e)) {
                      s = e;
                      break;
                    }
                  }
                  s > -1
                    ? this.didClick(s)
                    : 8 === e.which
                      ? (this.backspacePreventDefault && e.preventDefault(),
                        this.$emit("backspace"))
                      : 13 === e.which && this.$emit("tick");
                } else 13 === e.which && this.$emit("tick");
              },
              didShift() {
                // Shift key pressed - toggle capitals mode
                this.$emit("shift");
              },
              didUnShift() {
                // Shift key released - toggle back to lowercase
                this.$emit("unshift");
              },
              didClick(e) {
                // User clicked a key (or matched physical key to on-screen key)
                // Emits: selectedindex (Beekeeper), letter (with GPC for phonics)
                this.active &&
                  ((!this.connected && !this.hexSelected(e)) ||
                  (this.buzzwords &&
                    this.connected &&
                    this.canSelect(e) &&
                    !this.hexSelected(e))
                    ? ((this.qwerty && !this.beekeeper) ||
                        this.$emit("selectedindex", e),
                      this.$emit(
                        "letter",
                        this.keys[e],
                        this.phonics ? this.gpcs[e] : null,
                      ))
                    : this.buzzwords &&
                      this.connected &&
                      e === this.latestSelection &&
                      this.$emit("backspace"));
              },
              didMouseOver(e) {
                // Mouse hover over key - emit for phoneme audio playback
                this.phonics && this.$emit("hover-phonics", this.gpcs[e]);
              },
              hexSelected(e) {
                // Check if hexagon at index is already selected (Beekeeper mode)
                // Returns false if QWERTY mode without Beekeeper
                if (this.qwerty && !this.beekeeper) return !1;
                const t = this.selectedIndices.filter(function (t) {
                  if (t === e) return !0;
                });
                return t.length > 0;
              },
            },
          }),
        o = a,
        r = s(81656),
        c = (0, r.A)(o, i, n, !1, null, "60eb5d30", null),
        l = c.exports;
    },
    // ====== MODULE 86567: SettingsModal Component ======
    // Game settings/pause menu modal with audio and display controls
    // Features: Toggle music, toggle SFX (sound effects), resizable text
    86567: function (e, t, s) {
      s.d(t, {
        A: function () {
          return m;
        },
      });
      var i = function () {
          var e = this,
            t = e.$createElement,
            s = e._self._c || t;
          return s(
            "div",
            { staticClass: "modal is-active", attrs: { id: "resultModal" } },
            [
              s("div", {
                staticClass: "modal-background",
                on: {
                  click: function (t) {
                    return (t.preventDefault(), e.hideSettings(t));
                  },
                },
              }),
              s("div", { staticClass: "modal-content" }, [
                s("div", { attrs: { id: "settings-box" } }, [
                  e._m(0),
                  s("div", { staticClass: "content" }, [
                    e._m(1),
                    s("div", { staticClass: "setting" }, [
                      e._v(" Music "),
                      s(
                        "a",
                        {
                          attrs: { href: "#" },
                          on: {
                            click: function (t) {
                              return (t.preventDefault(), e.toggleMusic(t));
                            },
                          },
                        },
                        [
                          s("figure", { staticClass: "image" }, [
                            s("img", {
                              attrs: {
                                src:
                                  "/images/" +
                                  (e.musicOn
                                    ? "soundOnIcon.png"
                                    : "soundOffIcon.png"),
                              },
                            }),
                          ]),
                        ],
                      ),
                    ]),
                    s("div", { staticClass: "setting" }, [
                      e._v(" Sound FX "),
                      s(
                        "a",
                        {
                          attrs: { href: "#" },
                          on: {
                            click: function (t) {
                              return (t.preventDefault(), e.toggleSoundFX(t));
                            },
                          },
                        },
                        [
                          s("figure", { staticClass: "image" }, [
                            s("img", {
                              attrs: {
                                src:
                                  "/images/" +
                                  (e.soundFXOn
                                    ? "soundOnIcon.png"
                                    : "soundOffIcon.png"),
                              },
                            }),
                          ]),
                        ],
                      ),
                    ]),
                    e.number || "phonics" === e.location
                      ? e._e()
                      : s("div", { staticClass: "setting" }, [
                          e._v(" Letter Names "),
                          s(
                            "a",
                            {
                              attrs: { href: "#" },
                              on: {
                                click: function (t) {
                                  return (
                                    t.preventDefault(),
                                    e.toggleLetterNames(t)
                                  );
                                },
                              },
                            },
                            [
                              s("figure", { staticClass: "image" }, [
                                s("img", {
                                  attrs: {
                                    src:
                                      "/images/" +
                                      (e.letterNamesOn
                                        ? "soundOnIcon.png"
                                        : "soundOffIcon.png"),
                                  },
                                }),
                              ]),
                            ],
                          ),
                        ]),
                    e.pause
                      ? e._e()
                      : s("div", { staticClass: "setting" }, [
                          e._v(" Show Bonus Bar "),
                          s(
                            "a",
                            {
                              attrs: { href: "#" },
                              on: {
                                click: function (t) {
                                  return (
                                    t.preventDefault(),
                                    e.toggleTimers(t)
                                  );
                                },
                              },
                            },
                            [
                              s("figure", { staticClass: "image" }, [
                                s("img", {
                                  attrs: {
                                    src:
                                      "/images/" +
                                      (e.disableTimer
                                        ? "cross.png"
                                        : "tick.png"),
                                  },
                                }),
                              ]),
                            ],
                          ),
                        ]),
                    (e.pause && !e.number) || !e.allowInvertCalculator
                      ? e._e()
                      : s("div", { staticClass: "setting" }, [
                          e._v(" Invert Calculator "),
                          s(
                            "a",
                            {
                              staticClass: "has-text-dark",
                              attrs: { href: "#" },
                              on: {
                                click: function (t) {
                                  return (
                                    t.preventDefault(),
                                    e.toggleInvertCalc(t)
                                  );
                                },
                              },
                            },
                            [
                              s("figure", { staticClass: "image" }, [
                                e.invertCalcOn
                                  ? s("i", { staticClass: "mdi mdi-check" })
                                  : s("i", { staticClass: "mdi mdi-close" }),
                              ]),
                            ],
                          ),
                        ]),
                    !e.pause && e.canChangeFont
                      ? s(
                          "div",
                          { staticClass: "setting" },
                          [
                            s("label", { attrs: { for: "fontPreference" } }, [
                              e._v("Game Font"),
                            ]),
                            s(
                              "b-dropdown",
                              {
                                staticClass:
                                  "settings_modal_font_select_dropdown",
                                attrs: {
                                  "aria-role": "list",
                                  position: "is-top-left",
                                  value: e.fontPreference,
                                },
                                on: {
                                  change: function (t) {
                                    return e.setFont(t);
                                  },
                                },
                                scopedSlots: e._u(
                                  [
                                    {
                                      key: "trigger",
                                      fn: function (t) {
                                        t.active;
                                        return [
                                          s("b-button", {
                                            staticClass:
                                              "settings_modal_font_select_button",
                                            style: {
                                              "font-family":
                                                e.getFontFamilyFromKey(
                                                  e.fontPreference,
                                                ),
                                            },
                                            attrs: {
                                              label: e.getFontNameFromKey(
                                                e.fontPreference,
                                              ),
                                              type: "is-text",
                                            },
                                          }),
                                        ];
                                      },
                                    },
                                  ],
                                  null,
                                  !1,
                                  3510638343,
                                ),
                              },
                              e._l(e.fontOptions, function (t, i) {
                                return s(
                                  "b-dropdown-item",
                                  {
                                    key: i,
                                    style: {
                                      "font-family": e.getFontFamilyFromKey(i),
                                    },
                                    attrs: {
                                      "aria-role": "listitem",
                                      value: i,
                                    },
                                  },
                                  [e._v(" " + e._s(t) + " ")],
                                );
                              }),
                              1,
                            ),
                          ],
                          1,
                        )
                      : e._e(),
                    e.pause && e.lesson
                      ? s("div", { attrs: { id: "quitButton" } }, [
                          s(
                            "a",
                            {
                              attrs: { href: "#" },
                              on: {
                                click: function (t) {
                                  return (t.preventDefault(), e.quitLesson(t));
                                },
                              },
                            },
                            [
                              s("img", {
                                attrs: { src: "/images/quitButton.png" },
                              }),
                            ],
                          ),
                        ])
                      : e._e(),
                    e.pause && !e.lesson
                      ? s("div", { attrs: { id: "quitButton" } }, [
                          s(
                            "a",
                            {
                              attrs: { href: "#" },
                              on: {
                                click: function (t) {
                                  return (t.preventDefault(), e.quit(t));
                                },
                              },
                            },
                            [
                              s("img", {
                                attrs: { src: "/images/quitButton.png" },
                              }),
                            ],
                          ),
                        ])
                      : e._e(),
                  ]),
                ]),
              ]),
              s("button", {
                staticClass: "modal-close is-large",
                attrs: { "aria-label": "close" },
                on: {
                  click: function (t) {
                    return (t.preventDefault(), e.hideSettings(t));
                  },
                },
              }),
            ],
          );
        },
        n = [
          function () {
            var e = this,
              t = e.$createElement,
              s = e._self._c || t;
            return s("figure", { staticClass: "image is-4by3" }, [
              s("img", { attrs: { src: "/images/popup.png" } }),
            ]);
          },
          function () {
            var e = this,
              t = e.$createElement,
              s = e._self._c || t;
            return s("div", { attrs: { id: "title" } }, [
              s("figure", { staticClass: "image" }, [
                s("img", { attrs: { src: "/images/settings.png" } }),
              ]),
            ]);
          },
        ],
        a = (s(44114), s(13693)),
        o = s(7504),
        r = s(53235),
        c = s(43564),
        l = {
          // ====== SETTINGSMODAL COMPONENT CONFIGURATION ======
          name: "SettingsModal", // Component: pause menu/settings modal
          mixins: [a.A, r.A], // Mix in shared behaviors
          props: {
            pause: Boolean, // Is this a pause menu (vs. settings)?
            number: Boolean, // Number keyboard mode?
            location: 0, // Current game location/level
            ident: String, // User identifier
            allowInvertCalculator: Boolean, // Allow inverting calculator layout?
            lesson: { type: Boolean, default: !1 }, // Is lesson mode?
            hasCustomQuitHandler: { type: Boolean, default: !1 }, // Custom quit handler?
          },
          data() {
            return { config: o.A }; // Store config object
          },
          computed: {
            // ====== COMPUTED PROPERTIES: Derived from Vuex store ======
            musicOn() {
              return this.$store.state.musicOn; // Background music enabled?
            },
            soundFXOn() {
              return this.$store.state.soundFXOn; // Sound effects enabled?
            },
            letterNamesOn() {
              return this.$store.state.letterNamesOn; // Letter name audio enabled?
            },
            invertCalcOn() {
              return this.$store.state.invertCalcOn; // Calculator layout inverted?
            },
            disableTimer() {
              return this.$store.state.disableTimer; // Disable timer display?
            },
            fontPreference() {
              return this.$store.state.fontPreference; // Font choice (dyslexic, muli, sassoon, etc.)
            },
            canChangeFont() {
              return this.$store.state.canChangeFont; // Is font changeable?
            },
            fontOptions() {
              const e = { dyslexic: "Open Dyslexic", muli: "Muli" };
              return (
                "en-us" === this.$i18n.locale
                  ? (e.sassoonUs = "Sassoon")
                  : "en-za" === this.$i18n.locale
                    ? (e.sassoonZa = "Sassoon")
                    : ((e.sassoon = "Sassoon"),
                      (e.sassoonCurly = "Sassoon Curly")),
                e
              );
            },
          },
          methods: {
            // ====== EVENT HANDLERS ======
            
            // Hide the settings modal
            hideSettings() {
              this.$emit("hide");
            },
            
            // Convert font key to CSS font-family name
            // Supports: dyslexic, sassoon, sassoonCurly, sassoonUs, sassoonZa, muli
            getFontFamilyFromKey(e) {
              switch (e) {
                case "dyslexic":
                  return "OpenDyslexicAltaRegular";
                case "sassoon":
                  return "Sassoon";
                case "sassoonCurly":
                  return "SassoonCurly";
                case "sassoonUs":
                  return "SassoonUS";
                case "sassoonZa":
                  return "SassoonZA";
                case "muli":
                  return "Muli";
              }
            },
            
            // Get display name for font from key
            getFontNameFromKey(e) {
              return this.fontOptions[e] || "Default";
            },
            
            // Quit lesson mode and return to menu
            // Plays click sound and emits quit event
            quitLesson() {
              (this.$store.state.soundFXOn && this.$sounds.clickSound.play(),
                this.$emit("quit-episode"),
                this.$emit("hide"));
            },
            
            // Quit game - navigate based on game location
            // Handles: quizshed, number, spelling, phonics, assignments, main menu
            async quit() {
              if (
                (this.$store.state.soundFXOn && this.$sounds.clickSound.play(),
                this.hasCustomQuitHandler)
              )
                return void this.$emit("quit-handler");
              const e = await this.confirm({
                title: "Quit Game?",
                message: "Are you sure you want to quit this game?",
              });
              if (e)
                if ("quizshed" === this.location) {
                  const e = this.ident.charAt(0);
                  this.ident && "L" === e
                    ? (window.location.href =
                        this.config.serverInfo.quiz +
                        this.$i18n.locale +
                        "/lessons/" +
                        this.ident)
                    : this.ident && "Q" === e
                      ? (window.location.href =
                          this.config.serverInfo.quiz +
                          this.$i18n.locale +
                          "/browse/" +
                          this.ident)
                      : (window.location.href =
                          this.config.serverInfo.quiz +
                          this.$i18n.locale +
                          "/browse/");
                } else
                  "number" === this.location && this.$store.getters.hasNumber
                    ? this.$router.push({
                        name: "NumberMenu",
                        params: { lang: this.$i18n.locale },
                      })
                    : "spelling" === this.location &&
                        this.$store.getters.hasSpelling
                      ? this.$router.push({
                          name: "SpellingMenu",
                          params: { lang: this.$i18n.locale },
                        })
                      : "phonics" === this.location &&
                          this.$store.getters.hasSpelling
                        ? this.$router.push({
                            name: "Phonics Menu",
                            params: {
                              lang: this.$i18n.locale,
                              map_tab: this.$route.params.map_tab || "map",
                              grapheme: this.$route.params.grapheme || "",
                            },
                          })
                        : "assignments" === this.location
                          ? this.$router.push({
                              name: "Assignments",
                              params: { lang: this.$i18n.locale },
                            })
                          : null === this.location
                            ? this.$router.push({
                                name: "MainMenu",
                                params: { lang: this.$i18n.locale },
                              })
                            : this.$router.push({
                                name: "QuizMenu",
                                params: { lang: this.$i18n.locale },
                              });
            },
            async updateUserSetting(e, t) {
              await c.j.setSettings({ [e]: t });
            },
            toggleMusic() {
              const e = !this.musicOn;
              (this.$store.commit("SET_MUSIC", e),
                this.updateUserSetting("musicOn", e),
                e
                  ? ("unloaded" === this.$sounds.backgroundMusic.state() &&
                      this.$sounds.backgroundMusic.load(),
                    this.$sounds.backgroundMusic.play())
                  : this.$sounds.backgroundMusic.stop());
            },
            toggleSoundFX() {
              const e = !this.soundFXOn;
              (this.$store.commit("SET_SOUNDFX", e),
                this.updateUserSetting("soundFXOn", e),
                e &&
                  "unloaded" === this.$sounds.clickSound.state() &&
                  (this.$sounds.clickSound.load(),
                  this.$sounds.correctSound.load(),
                  this.$sounds.incorrectSound.load(),
                  this.$sounds.wellDoneSound.load()),
                this.$emit("setSoundFX", e));
            },
            toggleLetterNames() {
              const e = !this.letterNamesOn;
              (this.$store.commit("SET_LETTERNAMES", e),
                this.updateUserSetting("letterNamesOn", e));
            },
            toggleInvertCalc() {
              const e = !this.invertCalcOn;
              (this.$store.commit("SET_INVERTCALC", e),
                this.updateUserSetting("invertCalcOn", e));
            },
            toggleTimers() {
              const e = !this.disableTimer;
              (this.$store.commit("SET_DISABLE_TIMERS", e),
                this.updateUserSetting("disableTimer", e));
            },
            setFont(e) {
              (this.$store.commit("SET_FONT", e),
                this.updateUserSetting("fontPreference", e));
            },
          },
        },
        u = l,
        h = s(81656),
        d = (0, h.A)(u, i, n, !1, null, "155f7d83", null),
        m = d.exports;
    },
  },
]);
//# sourceMappingURL=3777.7e795376.js.map
