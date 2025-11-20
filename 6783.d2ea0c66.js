"use strict";
(self["webpackChunkgame"] = self["webpackChunkgame"] || []).push([
  [6783],
  {
    8639: function (t, s, e) {
      e.d(s, {
        Cf: function () {
          return l;
        },
        HP: function () {
          return o;
        },
      });
      e(62953);
      var a = e(31781),
        i = (e(13865), e(45963)),
        n = e(22735);
      function o(t) {
        return Object.keys(t);
      }
      function r(t) {
        if (!n.x2.includes(t))
          throw new i.o3(`Locale ${t} is not an adaptive spelling region`);
      }
      function l(t) {
        const s = t.locale;
        if (!n.x2.includes(s)) return !1;
        switch ((r(s), s)) {
          case "en_US":
          case "en_GB":
          case "en_ZA":
          case "en_AU":
            return !0;
          default:
            throw new a.N6(s);
        }
      }
    },
    46783: function (t, s, e) {
      (e.r(s),
        e.d(s, {
          default: function () {
            return M;
          },
        }));
      var a = function () {
          var t = this,
            s = t.$createElement,
            e = t._self._c || s;
          return e(
            "div",
            { class: { mainmenu: !0, sideOpen: t.menuOpen } },
            [
              e("div", { attrs: { id: "sideMenu" } }, [e("SideBarMenu")], 1),
              e("div", { staticClass: "mainContent" }, [
                e(
                  "a",
                  {
                    class: { "navbar-burger": !0, "is-active": t.menuOpen },
                    on: {
                      click: function (s) {
                        return (s.preventDefault(), t.toggleMenu(s));
                      },
                    },
                  },
                  [e("span"), e("span"), e("span")],
                ),
                e(
                  "section",
                  {
                    staticClass: "hero is-small",
                    staticStyle: { position: "relative", height: "6.5rem" },
                  },
                  [
                    t.$store.state.user
                      ? e("Avatar", {
                          staticClass: "mainMenuAvatar",
                          attrs: { user: t.$store.state.user, size: "2" },
                          nativeOn: {
                            click: function (s) {
                              return t.editAvatar(s);
                            },
                          },
                        })
                      : t._e(),
                    e("div", {}, [
                      e("div", { staticClass: "container has-text-centered" }, [
                        e(
                          "div",
                          {
                            staticStyle: {
                              "max-width": "18em",
                              margin: "10px auto 0",
                            },
                          },
                          [
                            e(
                              "router-link",
                              {
                                staticClass: "edshedlogo",
                                attrs: { to: "/" + t.$i18n.locale + "/" },
                              },
                              [
                                e("img", {
                                  staticClass: "img-responsive center-block",
                                  staticStyle: { height: "80px" },
                                  attrs: {
                                    src: "/images/logo-edshed.png",
                                    alt: "Logo",
                                  },
                                }),
                              ],
                            ),
                          ],
                          1,
                        ),
                      ]),
                    ]),
                  ],
                  1,
                ),
                e("section", { staticClass: "menu" }, [
                  e(
                    "div",
                    { staticClass: "container" },
                    [
                      t.$store.getters.hasSpelling ||
                      t.$store.getters.hasNumber ||
                      t.$store.hasPhonics
                        ? e(
                            "div",
                            {
                              staticClass:
                                "columns is-centered is-marginless summary-items is-hidden-mobile",
                            },
                            [
                              e(
                                "div",
                                {
                                  staticClass:
                                    "column is-8-desktop is-8-widescreen",
                                },
                                [
                                  e(
                                    "div",
                                    { staticClass: "tile is-ancestor" },
                                    [
                                      e(
                                        "div",
                                        { staticClass: "tile is-parent" },
                                        [
                                          e(
                                            "article",
                                            {
                                              staticClass: "tile is-child box",
                                            },
                                            [
                                              e("p", { staticClass: "title" }, [
                                                e("span", [
                                                  t._v("Assignments"),
                                                ]),
                                                t._v(" "),
                                                t.$store.state.user.school &&
                                                t.$store.getters.homeworks &&
                                                !t.$store.state.user.school
                                                  .teacher
                                                  ? e(
                                                      "span",
                                                      {
                                                        staticClass:
                                                          "tag is-danger",
                                                      },
                                                      [
                                                        t._v(
                                                          t._s(
                                                            t.$store.getters
                                                              .homeworks.length,
                                                          ),
                                                        ),
                                                      ],
                                                    )
                                                  : t._e(),
                                              ]),
                                              e(
                                                "p",
                                                {
                                                  staticClass:
                                                    "subtitle is-hidden-desktop-only",
                                                },
                                                [t._v(" Games set for you. ")],
                                              ),
                                              e(
                                                "router-link",
                                                {
                                                  staticClass:
                                                    "button is-small is-link  is-fullwidth",
                                                  attrs: {
                                                    tag: "button",
                                                    to:
                                                      "/" +
                                                      t.$i18n.locale +
                                                      "/assignments",
                                                  },
                                                },
                                                [
                                                  e("span", [t._v("View")]),
                                                  t._v(" "),
                                                  e(
                                                    "span",
                                                    { staticClass: "icon" },
                                                    [
                                                      e("i", {
                                                        staticClass:
                                                          "mdi mdi-chevron-right",
                                                      }),
                                                    ],
                                                  ),
                                                ],
                                              ),
                                            ],
                                            1,
                                          ),
                                        ],
                                      ),
                                      t.$store.getters.hasLimitLists
                                        ? t._e()
                                        : e(
                                            "div",
                                            { staticClass: "tile is-parent" },
                                            [
                                              e(
                                                "article",
                                                {
                                                  staticClass:
                                                    "tile is-child box",
                                                },
                                                [
                                                  e(
                                                    "p",
                                                    { staticClass: "title" },
                                                    [
                                                      t._v(" Challenges "),
                                                      t.challengeNotifications
                                                        .length
                                                        ? e(
                                                            "span",
                                                            {
                                                              staticClass:
                                                                "tag is-danger",
                                                            },
                                                            [
                                                              t._v(
                                                                t._s(
                                                                  t
                                                                    .challengeNotifications
                                                                    .length,
                                                                ),
                                                              ),
                                                            ],
                                                          )
                                                        : t._e(),
                                                    ],
                                                  ),
                                                  e(
                                                    "p",
                                                    {
                                                      staticClass:
                                                        "subtitle is-hidden-desktop-only",
                                                    },
                                                    [
                                                      t._v(
                                                        " Challenge others to play. ",
                                                      ),
                                                    ],
                                                  ),
                                                  e(
                                                    "router-link",
                                                    {
                                                      staticClass:
                                                        "button is-small is-link  is-fullwidth",
                                                      attrs: {
                                                        tag: "button",
                                                        to:
                                                          "/" +
                                                          t.$i18n.locale +
                                                          "/challenges",
                                                      },
                                                    },
                                                    [
                                                      e("span", [t._v("View")]),
                                                      t._v(" "),
                                                      e(
                                                        "span",
                                                        { staticClass: "icon" },
                                                        [
                                                          e("i", {
                                                            staticClass:
                                                              "mdi mdi-chevron-right",
                                                          }),
                                                        ],
                                                      ),
                                                    ],
                                                  ),
                                                ],
                                                1,
                                              ),
                                            ],
                                          ),
                                      e(
                                        "div",
                                        { staticClass: "tile is-parent" },
                                        [
                                          e(
                                            "article",
                                            {
                                              staticClass: "tile is-child box",
                                            },
                                            [
                                              e("p", { staticClass: "title" }, [
                                                t._v(" Leagues "),
                                              ]),
                                              e(
                                                "p",
                                                {
                                                  staticClass:
                                                    "subtitle is-hidden-desktop-only",
                                                },
                                                [
                                                  t._v(
                                                    " Player and class leagues. ",
                                                  ),
                                                ],
                                              ),
                                              e(
                                                "router-link",
                                                {
                                                  staticClass:
                                                    "button is-small is-link  is-fullwidth",
                                                  attrs: {
                                                    tag: "button",
                                                    to:
                                                      "/" +
                                                      t.$i18n.locale +
                                                      "/leagues",
                                                  },
                                                },
                                                [
                                                  e("span", [t._v("View")]),
                                                  t._v(" "),
                                                  e(
                                                    "span",
                                                    { staticClass: "icon" },
                                                    [
                                                      e("i", {
                                                        staticClass:
                                                          "mdi mdi-chevron-right",
                                                      }),
                                                    ],
                                                  ),
                                                ],
                                              ),
                                            ],
                                            1,
                                          ),
                                        ],
                                      ),
                                    ],
                                  ),
                                ],
                              ),
                            ],
                          )
                        : t._e(),
                      e(
                        "div",
                        { staticClass: "columns is-centered is-marginless" },
                        [
                          e(
                            "div",
                            {
                              staticClass:
                                "column  is-8-desktop is-8-widescreen",
                            },
                            [
                              e(
                                "b-field",
                                [
                                  e("p", { staticClass: "control" }, [
                                    e(
                                      "span",
                                      { staticClass: "button is-static" },
                                      [t._v("#")],
                                    ),
                                  ]),
                                  e("b-input", {
                                    attrs: {
                                      placeholder:
                                        "Enter 6-digit hive code to join game",
                                      pattern: "[0-9]{6}",
                                      "validation-message": " ",
                                      expanded: "",
                                    },
                                    model: {
                                      value: t.hiveCode,
                                      callback: function (s) {
                                        t.hiveCode = s;
                                      },
                                      expression: "hiveCode",
                                    },
                                  }),
                                  e("p", { staticClass: "control" }, [
                                    e(
                                      "button",
                                      {
                                        staticClass: "button is-link",
                                        on: { click: t.loadHiveGameData },
                                      },
                                      [t._v(" Join ")],
                                    ),
                                  ]),
                                ],
                                1,
                              ),
                            ],
                            1,
                          ),
                        ],
                      ),
                      t.showNewGameAd
                        ? e(
                            "div",
                            {
                              staticClass: "columns is-centered is-marginless",
                            },
                            [
                              e(
                                "div",
                                {
                                  staticClass:
                                    "column  is-8-desktop is-8-widescreen",
                                },
                                [
                                  e("a", { on: { click: t.goToNewGame } }, [
                                    t._m(0),
                                  ]),
                                ],
                              ),
                            ],
                          )
                        : t._e(),
                      t._l(t.gameRows, function (s, a) {
                        return e(
                          "div",
                          {
                            key: "game-row-" + a,
                            staticClass:
                              "columns is-centered game-images is-mobile is-marginless is-multiline",
                          },
                          t._l(
                            t.availableGames.slice(2 * a, 2 * a + 2),
                            function (s, i) {
                              return e(
                                "div",
                                {
                                  key: "game-" + a + "-" + i,
                                  staticClass:
                                    "column is-6-tablet is-4-desktop is-4-widescreen is-6-mobile",
                                },
                                [
                                  e(
                                    "div",
                                    { staticClass: "has-text-centered" },
                                    [
                                      e("figure", { staticClass: "image" }, [
                                        e("img", {
                                          attrs: {
                                            src: "/images/" + s.filename,
                                            alt: s.name + " Game",
                                          },
                                        }),
                                      ]),
                                      e(
                                        "router-link",
                                        {
                                          staticClass: "button is-large",
                                          class: s.buttonClass,
                                          attrs: {
                                            to:
                                              "/" +
                                              t.$i18n.locale +
                                              "/" +
                                              s.url,
                                            title: "Play " + s.name,
                                          },
                                        },
                                        [
                                          e("span", { staticClass: "icon" }, [
                                            e("i", {
                                              staticClass: "fas fa-gamepad",
                                            }),
                                          ]),
                                          e("span", [t._v("Play!")]),
                                          s.assignmentCount
                                            ? e(
                                                "div",
                                                {
                                                  staticClass:
                                                    "tags homework-counter",
                                                },
                                                [
                                                  e(
                                                    "span",
                                                    {
                                                      staticClass:
                                                        "tag is-danger",
                                                    },
                                                    [
                                                      t._v(
                                                        t._s(s.assignmentCount),
                                                      ),
                                                    ],
                                                  ),
                                                ],
                                              )
                                            : t._e(),
                                        ],
                                      ),
                                    ],
                                    1,
                                  ),
                                ],
                              );
                            },
                          ),
                          0,
                        );
                      }),
                    ],
                    2,
                  ),
                ]),
                e("footer", [
                  e(
                    "div",
                    {
                      staticClass: "container has-text-centered has-text-white",
                    },
                    [
                      e("p", { staticClass: "tag is-white" }, [
                        t._v(
                          " Copyright © EdShed " +
                            t._s(new Date().getFullYear()) +
                            " ",
                        ),
                      ]),
                    ],
                  ),
                ]),
              ]),
              e("footer", { staticClass: "nag" }, [
                t.$store.state.user.school && t.$store.state.user.school.teacher
                  ? e(
                      "div",
                      {
                        staticClass: "has-text-right",
                        attrs: { id: "teacherNag" },
                      },
                      [
                        t._v(" You are signed in as a teacher "),
                        e(
                          "a",
                          {
                            staticClass: "button is-warning is-small",
                            attrs: { href: t.svconfig.serverInfo.auth },
                          },
                          [t._v("Back")],
                        ),
                      ],
                    )
                  : t._e(),
              ]),
              t.showSettings
                ? e("SettingsModal", {
                    attrs: { pause: !1 },
                    on: { hide: t.hideSettingsModal },
                  })
                : t._e(),
              t.showInfo
                ? e("InfoModal", { on: { hide: t.hideInfoModal } })
                : t._e(),
              t.showAvatarEditor
                ? e("AvatarShop", {
                    attrs: { modal: "" },
                    on: { close: t.closeAvatarEditor },
                  })
                : t._e(),
            ],
            1,
          );
        },
        i = [
          function () {
            var t = this,
              s = t.$createElement,
              e = t._self._c || s;
            return e("div", { staticClass: "new-game-ad" }, [
              e("div", { staticClass: "new-game-ad__inner" }, [
                e("img", {
                  staticClass: "new-game-ad__logo",
                  attrs: {
                    src: "/images/beesieged_logo.png",
                    draggable: "false",
                  },
                }),
                e("p", [
                  t._v("A new game for "),
                  e("img", {
                    attrs: { src: "/images/logo.png", draggable: "false" },
                  }),
                ]),
              ]),
              e("div", { staticClass: "new-game-ad__tooltip" }, [
                e("div", { staticClass: "new-game-ad__tooltip__inner" }, [
                  e("p", [t._v("Available Now!")]),
                  e("p", [
                    t._v(
                      "An exciting new spelling game driven by Mastery Zone!",
                    ),
                  ]),
                ]),
              ]),
            ]);
          },
        ],
        n = e(91114),
        o =
          (e(16280),
          e(44114),
          e(18111),
          e(7588),
          e(84864),
          e(57465),
          e(27495),
          e(62953),
          e(31635)),
        r = e(18657),
        l = e(37422),
        c = e(56847),
        h = e(70913),
        u = e(86567),
        g = e(83326),
        d = e(70100),
        m = e(13693),
        p = e(7504),
        v = e(93523),
        C = e(8639),
        f = e(53235),
        _ = e(45963),
        w = e(43564);
      const b = 2;
      let k = class extends (0, r.Xe)(f.A, m.A, v.A) {
        constructor(...t) {
          (super(...t),
            (0, n.A)(this, "svconfig", p.A),
            (0, n.A)(this, "menuOpen", !1),
            (0, n.A)(this, "showAvatarEditor", !1),
            (0, n.A)(this, "showSettings", !1),
            (0, n.A)(this, "showInfo", !1),
            (0, n.A)(this, "hiveCode", ""),
            (0, n.A)(this, "challengeNotifications", []),
            (0, n.A)(this, "games", [
              {
                key: "phonics",
                name: "Phonics Shed",
                url: "phonicsmenu",
                filename: "phonics-game-image.png",
                buttonClass: "phonicsshed-button",
                assignmentCount: 0,
              },
              {
                key: "spelling",
                name: "Spelling Shed",
                url: "spelling",
                filename: "spelling-game-image.png",
                buttonClass: "is-warning",
                assignmentCount: 0,
              },
              {
                key: "grammar",
                name: "Grammar Arcade",
                url: "grammar",
                filename: "grammar-game-image.png",
                buttonClass: "is-warning",
                assignmentCount: 0,
              },
              {
                key: "number",
                name: "MathShed",
                url: "number",
                filename: "mathshed-game-image.png",
                buttonClass: "mathshed-button",
                assignmentCount: 0,
              },
              {
                key: "quiz",
                name: "QuizShed",
                url: "quizmenu",
                filename: "quiz-game-image.png",
                buttonClass: "quizshed-button",
                assignmentCount: 0,
              },
            ]));
        }
        mounted() {
          (this.setTheme("default"),
            this._store.state.user &&
              this._store.state.user.school &&
              (this.checkNotifications(),
              null === this._store.state.homeworks && this.loadHomeworks()),
            this.$route.query.hive &&
              ((this.hiveCode = this.$route.query.hive),
              this.loadHiveGameData()),
            this._store.state.user &&
              this._store.state.user.version !== b &&
              this.loadUser());
        }
        async loadUser() {
          const t = await w.j.getCurrentUser();
          this.setUserData(t);
        }
        get showNewGameAd() {
          const t = this._store.state.user;
          if (!t) return !1;
          const s = t.school;
          return !!s && (0, C.Cf)(s);
        }
        get availableGames() {
          const t = [];
          return (
            this.games.forEach((s) => {
              ("phonics" !== s.key ||
                !this.$store.getters.hasPhonics ||
                (this.$store.getters.hasLimitLists &&
                  !this.$store.getters.phonicsAssignmentCount) ||
                ((s.assignmentCount =
                  this.$store.getters.phonicsAssignmentCount),
                t.push(s)),
                "spelling" !== s.key ||
                  !this.$store.getters.hasSpelling ||
                  (this.$store.getters.hasLimitLists &&
                    !this.$store.getters.spellingAssignmentCount) ||
                  ((s.assignmentCount =
                    this.$store.getters.spellingAssignmentCount),
                  t.push(s)),
                "grammar" !== s.key ||
                  !this.$store.getters.hasGrammarArcade ||
                  (this.$store.getters.hasLimitLists &&
                    !this.$store.getters.grammarAssignmentCount) ||
                  ((s.assignmentCount =
                    this.$store.getters.grammarAssignmentCount),
                  t.push(s)),
                "number" !== s.key ||
                  !this.$store.getters.hasNumber ||
                  (this.$store.getters.hasLimitLists &&
                    !this.$store.getters.numberAssignmentCount) ||
                  ((s.assignmentCount =
                    this.$store.getters.numberAssignmentCount),
                  t.push(s)),
                "quiz" !== s.key ||
                  (this.$store.getters.hasLimitLists &&
                    !this.$store.getters.quizAssignmentCount) ||
                  ((s.assignmentCount =
                    this.$store.getters.quizAssignmentCount),
                  t.push(s)));
            }),
            t
          );
        }
        get gameRows() {
          return Math.max(1, Math.ceil(this.availableGames.length / 2));
        }
        get canPlayGrammarArcade() {
          return this._store.getters.hasGrammarArcade;
        }
        async checkNotifications() {
          try {
            this.challengeNotifications = await w.j.getChallengeNotifications();
          } catch (t) {
            t instanceof Error &&
              !(t instanceof _.w) &&
              this.alert({
                title: t.name,
                message: t.message,
                console: t.stack,
              });
          }
        }
        didTapInfoButton() {
          (this.$store.state.soundFXOn && this.$sounds.clickSound.play(),
            this.showInfoModal());
        }
        didTapLogoutButton() {
          this.$store.state.soundFXOn && this.$sounds.clickSound.play();
          const t = confirm("Are you sure you want to logout?");
          t && this.$router.push({ name: "Logout" });
        }
        toggleMenu() {
          this.menuOpen = !this.menuOpen;
        }
        showSettingsModal() {
          (this.$store.state.soundFXOn && this.$sounds.clickSound.play(),
            (this.showSettings = !0));
        }
        hideSettingsModal() {
          this.showSettings = !1;
        }
        editAvatar() {
          this.showAvatarEditor = !0;
        }
        closeAvatarEditor() {
          this.showAvatarEditor = !1;
        }
        showInfoModal() {
          this.showInfo = !0;
        }
        hideInfoModal() {
          this.showInfo = !1;
        }
        goToNewGame() {
          this.$router.push({ name: "Bee Sieged Menu" });
        }
        async loadHiveGameData() {
          const t = new RegExp(/^[0-9]{6}$/i);
          if (!t.test(this.hiveCode)) return;
          const s = parseInt(this.hiveCode);
          try {
            const t = await w.j.getHiveData(s),
              e = {
                list: t.list_ident,
                difficulty: t.difficulty,
                hive: t.room,
                hiveId: t.id,
                words: t.words.split(","),
                locale: t.locale,
                phonics: t.phonics,
                wordsData: t.wordsData,
                hubAudio: t.hub_audio,
                showLeagues: t.show_leagues,
                gameType: "spelling",
              };
            (this.$gtag.event("game", {
              event_category: "start",
              value: t.list_ident,
              event_label: t.difficulty,
            }),
              this.$router.push({
                name: "SpellingGame",
                params: { session: e, lang: this.$i18n.locale },
              }));
          } catch (e) {
            e instanceof Error &&
              this.alert({
                title: e.name,
                message: e.message,
                console: e.stack,
              });
          }
        }
        async loadHomeworks() {
          try {
            var t;
            if (
              this._store.state.user &&
              1 !==
                (null === (t = this._store.state.user.school) || void 0 === t
                  ? void 0
                  : t.teacher)
            ) {
              const t = await w.j.getHomework(
                {
                  id: this._store.state.user.id,
                  status: "active",
                  has_licence: !0,
                },
                void 0,
              );
              this._store.commit("SET_HOMEWORKS", t);
            }
          } catch (s) {
            this.$buefy.toast.open({
              message: "Could not load homeworks",
              position: "is-bottom",
              type: "is-danger",
            });
          }
        }
      };
      k = (0, o.Cg)(
        [
          (0, r.uA)({
            components: {
              Modal: h.A,
              SettingsModal: u.A,
              InfoModal: g.A,
              SideBarMenu: d.A,
              AvatarShop: c.A,
              Avatar: l.A,
            },
          }),
        ],
        k,
      );
      var A = k,
        $ = A,
        y = e(81656),
        S = (0, y.A)($, a, i, !1, null, "73e710d0", null),
        M = S.exports;
    },
    83326: function (t, s, e) {
      e.d(s, {
        A: function () {
          return c;
        },
      });
      var a = function () {
          var t = this,
            s = t.$createElement,
            e = t._self._c || s;
          return e(
            "div",
            { staticClass: "modal is-active", attrs: { id: "listsModal" } },
            [
              e("div", {
                staticClass: "modal-background",
                on: {
                  click: function (s) {
                    return (s.preventDefault(), t.hideInfo(s));
                  },
                },
              }),
              t._m(0),
              e("button", {
                staticClass: "modal-close is-large",
                attrs: { "aria-label": "close" },
                on: {
                  click: function (s) {
                    return (s.preventDefault(), t.hideInfo(s));
                  },
                },
              }),
            ],
          );
        },
        i = [
          function () {
            var t = this,
              s = t.$createElement,
              e = t._self._c || s;
            return e("div", { staticClass: "modal-content" }, [
              e("div", { staticClass: "info-box" }, [
                e("figure", { staticClass: "image is-4by3" }, [
                  e("img", { attrs: { src: "/images/popup.png" } }),
                ]),
                e("div", { staticClass: "content" }, [
                  e("p", [
                    t._v(
                      "Spelling Shed is an app made by Literacy Shed. Visit ",
                    ),
                    e(
                      "a",
                      {
                        attrs: {
                          href: "http://www.spellingshed.com",
                          target: "_blank",
                        },
                      },
                      [t._v("www.spellingshed.com")],
                    ),
                    t._v(" for more information and instructions."),
                  ]),
                  e("p", [
                    t._v("Contact "),
                    e("a", { attrs: { href: "mailto:support@edshed.com" } }, [
                      t._v("support@edshed.com"),
                    ]),
                    t._v(" for help and support."),
                  ]),
                  e("p", [
                    t._v("Dyslexia Font via "),
                    e(
                      "a",
                      {
                        attrs: {
                          href: "http://opendyslexic.org",
                          target: "_blank",
                        },
                      },
                      [t._v("opendyslexic.org")],
                    ),
                    t._v("."),
                  ]),
                ]),
              ]),
            ]);
          },
        ],
        n = {
          name: "InfoModal",
          methods: {
            hideInfo() {
              this.$emit("hide");
            },
          },
        },
        o = n,
        r = e(81656),
        l = (0, r.A)(o, a, i, !1, null, "7336fc4a", null),
        c = l.exports;
    },
  },
]);
//# sourceMappingURL=6783.d2ea0c66.js.map
